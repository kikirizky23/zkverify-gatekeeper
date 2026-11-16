// server.mjs — Proof Gatekeeper agent (GROTH16 proof pass, v1.1.0).
// Node 22 + snarkjs 0.7.6. Listens on $PORT (default 3000), handler POST /agent.
//
// Protocol (source of truth: ../build-spec.txt, §02; proving plan ../groth16-plan.md):
//   POST /agent
//   - Every inbound request carries x-agent-games-signature = HMAC-SHA256
//     (hex) of the RAW request body, keyed by AGENT_GAMES_HMAC_SECRET.
//     Verify BEFORE parsing JSON; reject on mismatch (401).
//   - Preflight  { "type": "agent-games.preflight.v1", ... }
//     → { "ok": true, "protocolVersion": "v1" }, signed.
//   - Task       { "type": "agent-games.proof-gatekeeper.v1", "task_id",
//                  "mode", "issued_at", "deadline_at", "input": {...} }
//     → { "decision": "APPROVE"|"REJECT", "reason_code": "...",
//         "proof_tx": "<echoed when present>",
//         "proof": "<Groth16 proof>", "public_signals": ["<13 decimal strings>"] }, signed.
//   - GROTH16: a proof is attached on every provable task (APPROVE and
//     REJECT). Proving is a BEST-EFFORT annotation AFTER the decision is
//     computed and recorded: on ANY proving failure/timeout the response is
//     the exact logic-only response (decision + reason_code), which costs
//     the same −2 as an omitted proof and never changes the decision.
//     VK_SUBSTITUTION tasks are logic-only by design (plan §6.2).
//   - Every response carries x-agent-games-signature over the raw body.
//   - Fail closed: any error/uncertainty → REJECT, never approve by default.
//   - 60s hard deadline: decision is synchronous microseconds; proving is
//     capped at a 10s hard timeout (measured ~1s), leaving 50s headroom.
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
import { generateProof } from './prove.mjs';

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
const PROVE_TIMEOUT_MS = 10_000; // hard proving timeout (plan §6.3)

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
// Atomic write (temp file + rename) so a crash mid-write cannot leave a
// corrupt state.json. Returns true on success, false on failure.
function saveState() {
  const tmpPath = STATE_PATH + '.tmp';
  try {
    fs.writeFileSync(tmpPath, JSON.stringify(state), 'utf8');
    fs.renameSync(tmpPath, STATE_PATH);
    return true;
  } catch (e) {
    console.error('WARN: could not persist state:', e.message);
    try {
      fs.rmSync(tmpPath, { force: true });
    } catch {}
    return false;
  }
}

// In-flight proving promises, keyed by task_id. A replay that arrives
// while the first request is still proving awaits this promise so it gets
// the SAME proof-bearing response — never the interim logic-only record
// (Codex review round 1, MAJOR). The promise always resolves (tryProve
// never throws; saveState never throws), so awaiting it cannot hang.
const inflight = new Map();

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

// ---- proving (Groth16, additive + fail-closed) ---------------------------
// tryProve returns { proof, public_signals } or null. Null means
// "logic-only" — the decision is unchanged. It NEVER throws.
// Skips proving by design when the proof's VK is missing or substituted
// (plan §6.2): the circuit only checks registeredVkHash == proofVkHash,
// so a proof for a substituted VK would carry the WRONG hash and fail
// platform verification; the REJECT is already correct without it.
async function tryProve(input, decision, taskId) {
  const regVk =
    typeof input.registered_vk === 'string'
      ? input.registered_vk.trim().toLowerCase()
      : '';
  const proofVk =
    typeof input.proof_vk === 'string' ? input.proof_vk.trim().toLowerCase() : '';
  if (!regVk || !proofVk || regVk !== proofVk) return null;

  // NOTE (accepted limitation, plan §6.3 + Codex review round 1, MAJOR):
  // the 10s timeout only races the promise — it does NOT cancel a
  // running generateProof(). A timed-out prove keeps running in the
  // background until it finishes. This is accepted because the measured
  // path is stable (~1s), the game sends at most 8 tasks/round, and the
  // timeout still guarantees the RESPONSE deadline (the response is sent
  // logic-only at 10s regardless). The plan explicitly prefers in-process
  // proving first and a killable child process only if load testing shows
  // instability. If proving ever exceeds 10s systematically on Railway,
  // move generateProof() into a child process with a hard kill.
  let timer;
  try {
    const out = await Promise.race([
      generateProof({
        taskId,
        minimum: input.minimum,
        publicBalance: input.public_balance,
        expiryBlock: input.expiry_block,
        currentBlock: input.current_block,
        recipient: input.recipient,
        conditionRecipient: input.condition_recipient,
        amount: input.amount,
        maxTransfer: input.max_transfer,
        proofVkHash: input.proof_vk,
        decision,
      })
        .then((r) => ({ ok: true, ...r }))
        .catch((e) => ({ ok: false, error: e })),
      new Promise((resolve) => {
        timer = setTimeout(
          () => resolve({ ok: false, error: new Error('prove timeout') }),
          PROVE_TIMEOUT_MS,
        );
      }),
    ]);
    if (!out || !out.ok) {
      console.error(`prove failed task ${taskId}: ${out?.error?.message || 'unknown'}`);
      return null;
    }
    console.log(
      `prove ok task ${taskId} taskIdField=${out.taskIdField} encoding=${out.taskIdEncoding} decision=${decision}`,
    );
    return { proof: out.proof, public_signals: out.publicSignals };
  } catch (e) {
    console.error(`prove failed task ${taskId}: ${e.message}`);
    return null;
  } finally {
    if (timer) clearTimeout(timer);
  }
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
    // If a first request is still proving, await its final response so
    // the replay gets the SAME proof-bearing response, not the interim
    // logic-only record (Codex review round 1, MAJOR).
    if (taskId && state.decisions[taskId]) {
      const pending = inflight.get(taskId);
      if (pending) {
        try {
          const finalResponse = await pending;
          sendSigned(res, 200, finalResponse);
        } catch {
          sendSigned(res, 200, state.decisions[taskId]);
        }
        return;
      }
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
    };

    // Record the decision FIRST (durable even if proving then fails).
    // Only the first owner of a proof_tx wins.
    // If this save fails, persistence is broken: skip proving and send
    // logic-only (Codex review round 2, MAJOR). A proof is only ever sent
    // when it is durably stored, so sent == stored for proof-bearing
    // responses. The correct decision is still sent even when the disk
    // fails — returning a 500 would cost the task outright.
    let persisted = true;
    if (taskId) {
      state.decisions[taskId] = response;
      const proofTx = env.input?.proof_tx;
      if (typeof proofTx === 'string' && proofTx) {
        if (!state.proofOwners[proofTx]) state.proofOwners[proofTx] = taskId;
      }
      persisted = saveState();
      if (!persisted) {
        console.error(`state save failed task ${taskId}: sending logic-only, proving skipped`);
      }
    }

    // Proving is a best-effort annotation AFTER the decision is recorded.
    // On any failure/timeout the response stays logic-only (today's exact
    // behaviour, −2 — never worse). Proving never changes the decision.
    // VK_SUBSTITUTION tasks are skipped inside tryProve (by design, §6.2).
    // The in-flight promise is tracked so a concurrent replay awaits the
    // final (proof-bearing) response instead of the interim record.
    let finalResponse = response;
    if (taskId && persisted) {
      const provePromise = (async () => {
        const proved = await tryProve(env.input || {}, result.decision, taskId);
        if (proved) {
          const withProof = {
            ...response,
            proof: proved.proof,
            public_signals: proved.public_signals,
          };
          state.decisions[taskId] = withProof;
          if (saveState()) {
            return withProof;
          }
          // Persist failed: send logic-only so the sent response matches
          // what is durably stored (Codex review round 1, MINOR). The
          // decision is unchanged; only the proof is withheld.
          console.error(
            `prove ok but state save failed task ${taskId}: sending logic-only`,
          );
          state.decisions[taskId] = response;
          return response;
        }
        return response;
      })();
      inflight.set(taskId, provePromise);
      try {
        finalResponse = await provePromise;
      } finally {
        inflight.delete(taskId);
      }
    }
    sendSigned(res, 200, finalResponse);
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
        mode: 'groth16',
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
    `gatekeeper listening on :${PORT} (POST /agent) — groth16 proofs on (fail-closed to logic-only)`,
  );
});
