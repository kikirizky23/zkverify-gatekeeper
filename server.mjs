// server.mjs — DUAL agent: Proof Gatekeeper (Groth16, v1.1.0) + Steal the VFY
// ("Optimal Strategy", v1.0.0). Node 22 + snarkjs 0.7.6.
// Listens on $PORT (default 3000), handler POST /agent.
//
// This file is gatekeeper-v2/server.mjs PLUS Steal routing. The Gatekeeper
// path is preserved EXACTLY (same decision engine, same proving, same
// state keys, same responses) so its harness still passes 26/26.
// Steal is additive: a new envelope branch, a second HMAC secret, a
// second state namespace, and a second circuit.
//
// Protocol (source of truth: ../build-spec.txt, §02 Gatekeeper, §06 Steal):
//   POST /agent
//   - Every inbound request carries x-agent-games-signature = HMAC-SHA256
//     (hex) of the RAW request body, keyed by the AGENT's own secret.
//     Both agents share this endpoint URL, so the HMAC is verified
//     against BOTH secrets (Gatekeeper first, then Steal); the response
//     is signed with the secret that verified the request. Verify
//     BEFORE parsing JSON; reject on mismatch (401).
//   - Preflight  { "type": "agent-games.preflight.v1", ... }
//     → { "ok": true, "protocolVersion": "v1" }, signed with the
//     verifying secret. (The platform preflights each agent separately
//     with that agent's secret.)
//   - Gatekeeper { "type": "agent-games.proof-gatekeeper.v1", ... }
//     → unchanged from v1.1.0 (decision + optional Groth16 proof).
//   - Steal turn { "eventId": "steal-the-vfy", "mode", "matchId",
//                  "turn", "issuedAt", "deadlineAt",
//                  "state": { selfBalance, opponentBalance,
//                             selfFortifiedUntilTurn,
//                             opponentFortifiedUntilTurn },
//                  "strategyCommitment": { "hash" },
//                  "resolverVersion", "nonce" }
//     → { "matchId", "turn", "action": { "type", "amount"? },
//         "policyProof": { "circuitVersion": "v1", "proof",
//                          "public_signals": ["<9 decimal strings>"] },
//         "agentTimestamp", "idempotencyKey" }, signed.
//     action.amount is present ONLY for EXTRACT (schema rejects it for
//     HOLD/FORTIFY even when 0). policyProof is present ONLY when a
//     proof was generated; otherwise the response is HOLD with NO
//     policyProof (fail-closed, -2, resolved as HOLD).
//     The vfy-policy circuit is SOLVED (circuit-steal/WIRING-TRACE.md):
//     generatePolicyProof returns a verifying Groth16 proof for every
//     turn whose action follows the circuit policy (strategy.mjs).
//     A proof failure (bad input, wrong action, timeout) still falls
//     back to HOLD with no proof — fail-closed, never a fabricated proof.
//   - Fail closed: any error/uncertainty → Gatekeeper REJECT, Steal HOLD.
//   - 60s hard deadline: Steal proving is capped at a 10s hard timeout
//     (measured Gatekeeper ~1s); the decision itself is synchronous.
//
// State (state.json next to this file, or $STATE_PATH):
//   Gatekeeper (unchanged): { proofOwners: {...}, decisions: {...} }
//   Steal (new namespace):  { stealMatches: {
//     "<matchId>": { "<turn>": { action, policyProof?, idempotencyKey,
//                                agentTimestamp } } } }
// Same (matchId, turn) replayed → stored response returned verbatim
// (idempotent). A turn is recorded BEFORE proving (durable even if
// proving then fails); a proof is only ever attached when it is
// durably stored.

import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide, issuedAtSane } from './decision.mjs';
import { generateProof } from './prove.mjs';
import { decideSteal } from './strategy.mjs';
import { generatePolicyProof } from './prove-steal.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
// Two per-event secrets. NEVER hardcode or print either. Both are
// required: this endpoint serves both agents, and a missing secret
// would make one agent unverifiable (401 for every request).
const GK_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const STEAL_SECRET = process.env.STEAL_HMAC_SECRET || '';
const STATE_PATH =
  process.env.STATE_PATH || path.join(__dirname, 'state.json');

if (!GK_SECRET) {
  console.error(
    'FATAL: AGENT_GAMES_HMAC_SECRET is not set. ' +
      'Copy it from the platform dashboard (Rotate Secret) and set it in the environment. ' +
      'Refusing to start with a placeholder secret (see build-spec §02/§05).',
  );
  process.exit(1);
}
if (!STEAL_SECRET) {
  console.error(
    'FATAL: STEAL_HMAC_SECRET is not set. ' +
      'Copy it from the platform dashboard for the kixbt-steal agent ' +
      '(Rotate Secret) and set it in the environment. ' +
      'Refusing to start with a placeholder secret (see build-spec §06).',
  );
  process.exit(1);
}

// The registered Steal commitment (dashboard, kixbt-steal, re-registered
// 2026-11-16T14:53:26Z). This is Poseidon_73(STRATEGY_PARAMS, salt=1) —
// NOT the vfyPolicy vk_hash (0x6c56509f…be047). The vk_hash was registered
// by mistake and can never match a proof's commitment (254-bit preimage),
// which is why every Steal proof was rejected with proof_failure −2.
// A turn whose strategyCommitment.hash differs is answered HOLD
// (fail-closed); the platform freezes the commitment at pairing.
// MUST match prove-steal.mjs::REGISTERED_COMMITMENT_HEX.
const STEAL_COMMITMENT =
  '0x16b3ed1bc216831d62c8e5c3957d0b7dc6e6c880885092f54357aacc826dc0ef';

const MAX_BODY = 1_000_000; // 1 MB — envelopes are a few KB
const PROVE_TIMEOUT_MS = 10_000; // hard proving timeout (plan §6.3)

// ---- state ---------------------------------------------------------------
let state = { proofOwners: {}, decisions: {}, stealMatches: {} };
try {
  const raw = fs.readFileSync(STATE_PATH, 'utf8');
  const parsed = JSON.parse(raw);
  if (parsed && typeof parsed === 'object') {
    if (parsed.proofOwners && typeof parsed.proofOwners === 'object')
      state.proofOwners = parsed.proofOwners;
    if (parsed.decisions && typeof parsed.decisions === 'object')
      state.decisions = parsed.decisions;
    if (parsed.stealMatches && typeof parsed.stealMatches === 'object')
      state.stealMatches = parsed.stealMatches;
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

// In-flight proving promises, keyed by task_id (Gatekeeper) and by
// "steal:<matchId>:<turn>" (Steal). A replay that arrives while the
// first request is still proving awaits this promise so it gets the
// SAME proof-bearing response — never the interim logic-only record
// (Codex review round 1, MAJOR, Gatekeeper). The promise always
// resolves (tryProve / tryProveSteal never throw; saveState never
// throws), so awaiting it cannot hang.
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

// Identify which agent's secret verifies this request. Returns
// 'gatekeeper' | 'steal' | null. Gatekeeper is tried first (it is the
// older agent); the two secrets are independent 64-hex strings, so a
// valid signature matches exactly one of them.
function verifyAgent(rawBody, header) {
  if (signatureValid(GK_SECRET, rawBody, header)) return 'gatekeeper';
  if (signatureValid(STEAL_SECRET, rawBody, header)) return 'steal';
  return null;
}

function secretFor(agent) {
  return agent === 'steal' ? STEAL_SECRET : GK_SECRET;
}

// ---- helpers ---------------------------------------------------------------
function sendSigned(res, status, obj, secret) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'content-type': 'application/json',
    'x-agent-games-signature': hmacHex(secret, body),
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

// ---- proving (Groth16, Gatekeeper — UNCHANGED from v1.1.0) ---------------
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

// ---- proving (Groth16, Steal — best-effort, fail-closed) ------------------
// tryProveSteal returns { proof, public_signals } or null. Null means
// "no proof" — the caller returns HOLD. It NEVER throws.
// The circuit is SOLVED (circuit-steal/WIRING-TRACE.md): a valid turn
// (action = the circuit-policy action for the balances) generates a
// verifying proof. Null only on genuine failure (bad input, wrong
// action, timeout) — that is the intended fail-closed behaviour, NOT a
// bug to work around by patching the wasm or by submitting an
// unverified proof.
async function tryProveSteal({ matchId, turn, state: st, action }) {
  let timer;
  try {
    const out = await Promise.race([
      generatePolicyProof({ matchId, turn, state: st, action })
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
      console.error(
        `steal prove failed match ${matchId} turn ${turn}: ${out?.error?.message || 'unknown'}`,
      );
      return null;
    }
    console.log(`steal prove ok match ${matchId} turn ${turn} action=${action.type}`);
    return { proof: out.proof, public_signals: out.publicSignals };
  } catch (e) {
    console.error(`steal prove failed match ${matchId} turn ${turn}: ${e.message}`);
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
    // No agent identified yet (body unreadable) — sign with the
    // Gatekeeper secret; the platform treats a 413 as a failure either way.
    sendSigned(res, 413, { ok: false, error: 'body_too_large' }, GK_SECRET);
    return;
  }

  // 1. Verify HMAC over the RAW body BEFORE parsing (spec §02, §05).
  // Both agents share this endpoint; the request is verified against
  // the agent's own secret and the response is signed with that secret.
  const agent = verifyAgent(raw, req.headers['x-agent-games-signature']);
  if (!agent) {
    sendSigned(res, 401, { ok: false, error: 'bad_signature' }, GK_SECRET);
    return;
  }
  const secret = secretFor(agent);

  let env;
  try {
    env = JSON.parse(raw.toString('utf8'));
  } catch {
    sendSigned(res, 400, { ok: false, error: 'invalid_json' }, secret);
    return;
  }
  if (!env || typeof env !== 'object') {
    sendSigned(res, 400, { ok: false, error: 'missing_type' }, secret);
    return;
  }

  // 2. Preflight — must pass for the platform to mark the agent active.
  // Respond unconditionally after HMAC (never fail preflight on clock skew).
  // The platform preflights each agent with that agent's secret; the
  // response is signed with the secret that verified the request.
  if (env.type === 'agent-games.preflight.v1') {
    sendSigned(res, 200, { ok: true, protocolVersion: 'v1' }, secret);
    return;
  }

  // 3. Gatekeeper task. (UNCHANGED from v1.1.0, except the agent-match
  // check below, which is new: a Gatekeeper task must be signed with
  // the Gatekeeper secret. A task signed with the Steal secret is a
  // cross-agent error and is rejected, not routed to the Gatekeeper.)
  if (env.type === 'agent-games.proof-gatekeeper.v1') {
    if (agent !== 'gatekeeper') {
      sendSigned(res, 401, { ok: false, error: 'bad_agent' }, secret);
      return;
    }
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
          sendSigned(res, 200, finalResponse, secret);
        } catch {
          sendSigned(res, 200, state.decisions[taskId], secret);
        }
        return;
      }
      sendSigned(res, 200, state.decisions[taskId], secret);
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
    sendSigned(res, 200, finalResponse, secret);
    return;
  }

  // 4. Steal the VFY turn. Routed by eventId (not by `type`).
  // Agent-match: a Steal turn must be signed with the Steal secret.
  // (Codex review round 1, MAJOR: without this, a request signed with
  // the Gatekeeper secret could retrieve a stored Steal response.)
  if (env.eventId === 'steal-the-vfy') {
    if (agent !== 'steal') {
      sendSigned(res, 401, { ok: false, error: 'bad_agent' }, secret);
      return;
    }
    const matchId = typeof env.matchId === 'string' ? env.matchId : '';
    // Turn must be a safe integer (Codex review round 3, MINOR): do NOT
    // Math.trunc it — turn 1.5 would become 1, pass the range check,
    // and be stored under turn 1, poisoning a later legitimate turn 1.
    // A fractional/unsafe turn becomes 0, fails the 1..20 check below,
    // and returns an uncached HOLD.
    const turnRaw = Number(env.turn);
    const turn = Number.isSafeInteger(turnRaw) ? turnRaw : 0;
    const turnKey = String(turn);
    const inflightKey = `steal:${matchId}:${turnKey}`;
    const idempotencyKey =
      typeof env.nonce === 'string' && env.nonce
        ? env.nonce
        : `${matchId}:${turnKey}:${Date.now()}`;
    const agentTimestamp = new Date().toISOString();

    // Validate FIRST, before any replay lookup or persistence.
    // (Codex review round 1, MAJOR: persisting an invalid turn would
    // poison the idempotency record for a later legitimate turn.)
    // Any missing/mismatched required field is treated as HOLD with no
    // proof (build-spec §06). A wrong strategyCommitment.hash is also
    // HOLD (the platform freezes the commitment at pairing; a different
    // hash means this turn is not for our registered strategy).
    // An invalid turn is returned UNCACHED (never stored), so a later
    // valid turn for the same (matchId, turn) is processed fresh.
    const st = env.state && typeof env.state === 'object' ? env.state : null;
    const commitmentHash =
      env.strategyCommitment && typeof env.strategyCommitment.hash === 'string'
        ? env.strategyCommitment.hash.trim().toLowerCase()
        : '';
    const toNum = (v) => {
      if (v === undefined || v === null || v === '') return null;
      const n = Number(v);
      // Non-negative SAFE INTEGER, matching decideSteal's accepted domain
      // (Codex review round 2, MAJOR): a fractional or unsafe-integer
      // balance must fail validation HERE (uncached HOLD) rather than
      // reach decideSteal, return HOLD, and get persisted as the turn's
      // record (which would poison a later legitimate request).
      if (!Number.isSafeInteger(n) || n < 0) return null;
      return n;
    };
    const usable =
      !!matchId &&
      turn >= 1 &&
      turn <= 20 &&
      !!st &&
      toNum(st.selfBalance) !== null &&
      toNum(st.opponentBalance) !== null &&
      commitmentHash === STEAL_COMMITMENT.toLowerCase();
    if (!usable) {
      sendSigned(
        res,
        200,
        {
          matchId,
          turn,
          action: { type: 'HOLD' },
          agentTimestamp,
          idempotencyKey,
        },
        secret,
      );
      return;
    }

    // Idempotent replay: same (matchId, turn) → same stored response.
    // Only valid turns reach here, so a stored record is always a
    // legitimate turn. If a first request is still proving, await its
    // final response.
    if (state.stealMatches[matchId]?.[turnKey]) {
      const pending = inflight.get(inflightKey);
      if (pending) {
        try {
          const finalResponse = await pending;
          sendSigned(res, 200, finalResponse, secret);
        } catch {
          sendSigned(res, 200, state.stealMatches[matchId][turnKey], secret);
        }
        return;
      }
      sendSigned(res, 200, state.stealMatches[matchId][turnKey], secret);
      return;
    }

    let action = { type: 'HOLD' };
    try {
      action = decideSteal(st, turn);
    } catch {
      action = { type: 'HOLD' };
    }

    // Build the response. action.amount is present ONLY for EXTRACT
    // (schema rejects it for HOLD/FORTIFY even when 0).
    const response = {
      matchId,
      turn,
      action:
        action.type === 'EXTRACT'
          ? { type: 'EXTRACT', amount: action.amount }
          : { type: action.type },
      agentTimestamp,
      idempotencyKey,
    };

    // Record the turn FIRST (durable even if proving then fails).
    // A proof is only ever attached when it is durably stored.
    let persisted = true;
    if (!state.stealMatches[matchId]) state.stealMatches[matchId] = {};
    state.stealMatches[matchId][turnKey] = response;
    persisted = saveState();
    if (!persisted) {
      console.error(`steal state save failed match ${matchId} turn ${turn}: proving skipped`);
    }

    // Proving is a best-effort annotation AFTER the turn is recorded.
    // On any failure/timeout the response stays HOLD-with-no-proof
    // (the platform resolves it as HOLD, -2 — never worse than the
    // no-proof baseline). Proving never changes the action, EXCEPT:
    // when the proof cannot be generated the response action is HOLD
    // (fail-closed) rather than the strategy action, because the
    // platform resolves a proof-less turn as HOLD anyway — declaring
    // an EXTRACT that will not be applied would be misleading.
    // When the proof IS generated, the strategy action is returned
    // WITH the proof (the normal case now that the circuit is solved).
    let finalResponse = response;
    if (persisted) {
      const provePromise = (async () => {
        const proved = await tryProveSteal({ matchId, turn, state: st, action });
        if (proved) {
          const withProof = {
            ...response,
            policyProof: {
              circuitVersion: 'v1',
              proof: proved.proof,
              public_signals: proved.public_signals,
            },
          };
          state.stealMatches[matchId][turnKey] = withProof;
          if (saveState()) {
            return withProof;
          }
          console.error(
            `steal prove ok but state save failed match ${matchId} turn ${turn}: sending HOLD, no proof`,
          );
          state.stealMatches[matchId][turnKey] = response;
          return {
            ...response,
            action: { type: 'HOLD' },
          };
        }
        // No proof (circuit blocker): fail closed to HOLD, no proof.
        const holdResponse = {
          ...response,
          action: { type: 'HOLD' },
        };
        state.stealMatches[matchId][turnKey] = holdResponse;
        saveState();
        return holdResponse;
      })();
      inflight.set(inflightKey, provePromise);
      try {
        finalResponse = await provePromise;
      } finally {
        inflight.delete(inflightKey);
      }
    }
    sendSigned(res, 200, finalResponse, secret);
    return;
  }

  // 5. Unknown envelope type → fail closed.
  sendSigned(res, 400, { ok: false, error: 'unknown_type' }, secret);
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
      // Health is public (no HMAC); it only reports liveness + mode.
      // It is signed with the Gatekeeper secret for consistency with
      // v1.1.0 (the health response itself carries no sensitive data).
      sendSigned(
        res,
        200,
        {
          ok: true,
          service: 'proof-gatekeeper+steal-the-vfy',
          protocolVersion: 'v1',
          mode: 'groth16',
          steal: 'optimal-strategy-v1',
        },
        GK_SECRET,
      );
      return;
    }
    sendSigned(res, 404, { ok: false, error: 'not_found' }, GK_SECRET);
  } catch (e) {
    // Last-resort fail closed. (Response signing still applies.)
    try {
      sendSigned(res, 500, { ok: false, error: 'internal_error' }, GK_SECRET);
    } catch {
      res.destroy();
    }
  }
});

server.listen(PORT, () => {
  console.log(
    `gatekeeper+steal listening on :${PORT} (POST /agent) — groth16 proofs on (fail-closed to logic-only / HOLD-no-proof)`,
  );
});
