// server.mjs — Proof Gatekeeper agent (LOGIC-ONLY pass).
// Node 22 stdlib only. Listens on $PORT (default 3000), handler POST /agent.
//
// Protocol (source of truth: ../build-spec.txt, §02):
//   POST /agent
//   - Every inbound request carries x-agent-games-signature = HMAC-SHA256
//     (hex) of the RAW request body, keyed by AGENT_GAMES_HMAC_SECRET.
//     Verify BEFORE parsing JSON; reject on mismatch (401).
//   - Preflight  { "type": "agent-games.preflight.v1", ... }
//     → { "ok": true, "protocolVersion": "v1" }, signed.
//   - Task       { "type": "agent-games.proof-gatekeeper.v1", "task_id",
//                  "mode", "issued_at", "deadline_at", "input": {...} }
//     → { "decision": "APPROVE"|"REJECT", "reason_code": "...",
//         "proof_tx": "<echoed when present>" }, signed.
//   - LOGIC-ONLY: `proof` / `public_signals` are OMITTED. Per the spec an
//     omitted proof costs −2; a correct decision still scores +12 −2.
//     (Groth16/snarkjs proof generation is a later pass, not this build.)
//   - Every response carries x-agent-games-signature over the raw body.
//   - Fail closed: any error/uncertainty → REJECT, never approve by default.
//   - 60s hard deadline: decision logic is synchronous microseconds.
//
// State (state.json next to this file, or $STATE_PATH):
//   { "proofOwners": { "<proof_tx>": "<task_id>" },
//     "decisions":   { "<task_id>": { decision, reason_code, proof_tx } } }
// Same task_id replayed → stored decision is returned verbatim (idempotent).
// Same proof_tx on a different task_id → PROOF_REUSED.

import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide, issuedAtSane } from './decision.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const STATE_PATH =
  process.env.STATE_PATH || path.join(__dirname, 'state.json');

if (!SECRET) {
  console.error(
    'FATAL: AGENT_GAMES_HMAC_SECRET is not set. ' +
      'Copy it from the platform dashboard (Rotate Secret) and set it in the environment. ' +
      'Refusing to start with a placeholder secret (see build-spec §02/§05).',
  );
  process.exit(1);
}

const MAX_BODY = 1_000_000; // 1 MB — envelopes are a few KB

// ---- state ---------------------------------------------------------------
let state = { proofOwners: {}, decisions: {} };
try {
  const raw = fs.readFileSync(STATE_PATH, 'utf8');
  const parsed = JSON.parse(raw);
  if (parsed && typeof parsed === 'object') {
    if (parsed.proofOwners && typeof parsed.proofOwners === 'object')
      state.proofOwners = parsed.proofOwners;
    if (parsed.decisions && typeof parsed.decisions === 'object')
      state.decisions = parsed.decisions;
  }
} catch {
  // missing/corrupt state: start empty (fail safe — reuse detection only
  // loses history it never had; decisions are recomputed, not invented)
}
function saveState() {
  try {
    fs.writeFileSync(STATE_PATH, JSON.stringify(state), 'utf8');
  } catch (e) {
    console.error('WARN: could not persist state:', e.message);
  }
}

// ---- HMAC ----------------------------------------------------------------
function hmacHex(secret, body) {
  return crypto.createHmac('sha256', secret).update(body).digest('hex');
}

// Constant-time compare. Accepts an optional "sha256=" prefix on the header
// (spec shows a bare hex value; the prefix is tolerated, never required).
function signatureValid(secret, rawBody, header) {
  if (!header || typeof header !== 'string') return false;
  const given = header.startsWith('sha256=') ? header.slice(7) : header;
  const expected = hmacHex(secret, rawBody);
  const a = Buffer.from(given.trim().toLowerCase(), 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// ---- helpers ---------------------------------------------------------------
function sendSigned(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'content-type': 'application/json',
    'x-agent-games-signature': hmacHex(SECRET, body),
  });
  res.end(body);
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// ---- /agent ---------------------------------------------------------------
async function handleAgent(req, res) {
  let raw;
  try {
    raw = await readRawBody(req);
  } catch (e) {
    sendSigned(res, 413, { ok: false, error: 'body_too_large' });
    return;
  }

  // 1. Verify HMAC over the RAW body BEFORE parsing (spec §02, §05).
  if (!signatureValid(SECRET, raw, req.headers['x-agent-games-signature'])) {
    sendSigned(res, 401, { ok: false, error: 'bad_signature' });
    return;
  }

  let env;
  try {
    env = JSON.parse(raw.toString('utf8'));
  } catch {
    sendSigned(res, 400, { ok: false, error: 'invalid_json' });
    return;
  }
  if (!env || typeof env !== 'object' || typeof env.type !== 'string') {
    sendSigned(res, 400, { ok: false, error: 'missing_type' });
    return;
  }

  // 2. Preflight — must pass for the platform to mark the agent active.
  // Respond unconditionally after HMAC (never fail preflight on clock skew).
  if (env.type === 'agent-games.preflight.v1') {
    sendSigned(res, 200, { ok: true, protocolVersion: 'v1' });
    return;
  }

  // 3. Gatekeeper task.
  if (env.type === 'agent-games.proof-gatekeeper.v1') {
    const taskId = typeof env.task_id === 'string' ? env.task_id : '';

    // Idempotent replay: same task_id → same stored decision.
    if (taskId && state.decisions[taskId]) {
      sendSigned(res, 200, state.decisions[taskId]);
      return;
    }

    let result;
    try {
      // Grossly stale/future-dated envelope → fail closed.
      if (!issuedAtSane(env.issued_at)) {
        result = { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
      } else {
        const input =
          env.input && typeof env.input === 'object' ? env.input : {};
        result = decide(input, (proofTx) => {
          const owner = state.proofOwners[proofTx];
          // A proof_tx owned by THIS task_id is a replay, handled above;
          // any other owner means reuse.
          return owner && owner !== taskId ? owner : null;
        });
      }
    } catch {
      // Any engine error → fail closed, never approve by default.
      result = { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
    }

    const response = {
      decision: result.decision,
      reason_code: result.reason_code,
      ...(typeof env.input?.proof_tx === 'string' && env.input.proof_tx
        ? { proof_tx: env.input.proof_tx }
        : {}),
      // NOTE (logic-only): `proof` and `public_signals` are intentionally
      // omitted. Cost: −2 per task; correct decision still scores +12 −2.
    };

    // Record outcome (only first owner of a proof_tx wins).
    if (taskId) {
      state.decisions[taskId] = response;
      const proofTx = env.input?.proof_tx;
      if (typeof proofTx === 'string' && proofTx) {
        if (!state.proofOwners[proofTx]) state.proofOwners[proofTx] = taskId;
      }
      saveState();
    }
    sendSigned(res, 200, response);
    return;
  }

  // 4. Unknown envelope type → fail closed.
  sendSigned(res, 400, { ok: false, error: 'unknown_type' });
}

// ---- server ----------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || '/', 'http://localhost');
    if (req.method === 'POST' && url.pathname === '/agent') {
      await handleAgent(req, res);
      return;
    }
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/health')) {
      sendSigned(res, 200, {
        ok: true,
        service: 'proof-gatekeeper',
        protocolVersion: 'v1',
        mode: 'logic-only',
      });
      return;
    }
    sendSigned(res, 404, { ok: false, error: 'not_found' });
  } catch (e) {
    // Last-resort fail closed. (Response signing still applies.)
    try {
      sendSigned(res, 500, { ok: false, error: 'internal_error' });
    } catch {
      res.destroy();
    }
  }
});

server.listen(PORT, () => {
  console.log(
    `gatekeeper listening on :${PORT} (POST /agent) — logic-only, proof omitted (−2/task)`,
  );
});
