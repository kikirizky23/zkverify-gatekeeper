// harness-steal.mjs — local test harness for the Steal the VFY branch.
// Spawns steal-v2/server.mjs on a test port with DUMMY secrets, then:
//  (A) unit-tests the "Optimal Strategy" (strategy.mjs) decision rules
//      — these MUST match the vfy-policy circuit policy exactly
//      (circuit-steal/WIRING-TRACE.md), or no proof can be generated;
//  (B) sends signed Steal turn envelopes and asserts the HTTP behaviour
//      (routing, HMAC, fail-closed HOLD, idempotency, shape);
//  (C) confirms the vfy-policy proof generation SUCCEEDS for a valid
//      turn and the proof VERIFIES against circuit-steal/vk.json.
// Exit 0 = all pass, 1 = any failure. No network beyond localhost.
// Usage: node harness-steal.mjs
// NOTE: the circuit is SOLVED (16 Nov 2026). A valid turn returns the
// strategy action + a verifying policyProof. Invalid turns still fail
// closed to HOLD with no proof.
import http from 'node:http';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { decideSteal, POLICY } from './strategy.mjs';
import {
  generatePolicyProof,
  verifyPolicyProof,
  encodeMatchId,
  STRATEGY_PARAMS,
  REGISTERED_COMMITMENT,
} from './prove-steal.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = 3105;
const GK_SECRET = 'dummy-test-secret-NEVER-USE-IN-PRODUCTION';
const STEAL_SECRET = 'dummy-steal-secret-NEVER-USE-IN-PRODUCTION';
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'steal-harness-'));
const STATE_PATH = path.join(TMP, 'state.json');
// Envelope commitment hash used by the harness (must equal the
// REGISTERED commitment — was the vk_hash, fixed 2026-11-16).
const COMMITMENT =
  '0x16b3ed1bc216831d62c8e5c3957d0b7dc6e6c880885092f54357aacc826dc0ef';

let passed = 0;
let failed = 0;
const results = [];
function check(name, ok, detail = '') {
  results.push(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
  if (ok) passed++;
  else failed++;
}

// ---- client helpers ------------------------------------------------------
function hmacHex(secret, body) {
  return crypto.createHmac('sha256', secret).update(body).digest('hex');
}
function request({ method = 'POST', path = '/agent', body, secret, sign = true, rawBody }) {
  return new Promise((resolve, reject) => {
    const data = rawBody !== undefined ? rawBody : body !== undefined ? JSON.stringify(body) : '';
    const headers = { 'content-type': 'application/json' };
    if (sign) headers['x-agent-games-signature'] = hmacHex(secret || STEAL_SECRET, data);
    const req = http.request(
      { host: '127.0.0.1', port: PORT, path, method, headers },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          }),
        );
      },
    );
    req.on('error', reject);
    req.end(data);
  });
}
function sigValid(res, secret) {
  const given = res.headers['x-agent-games-signature'];
  if (!given) return false;
  const expected = hmacHex(secret, res.body);
  const a = Buffer.from(given, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const parse = (r) => {
  try {
    return JSON.parse(r.body);
  } catch {
    return null;
  }
};

// ---- envelope builder (from build-spec §06 example) -----------------------
function turnEnv(overrides = {}) {
  const now = new Date();
  return {
    protocolVersion: 'v1',
    eventId: 'steal-the-vfy',
    mode: 'competition',
    matchId: '9f4e1b2a-1111-4222-8333-444455556666',
    turn: 3,
    issuedAt: now.toISOString(),
    deadlineAt: new Date(now.getTime() + 60000).toISOString(),
    state: {
      selfBalance: '95',
      opponentBalance: '105',
      selfFortifiedUntilTurn: null,
      opponentFortifiedUntilTurn: null,
    },
    strategyCommitment: { hash: COMMITMENT },
    resolverVersion: 'v1',
    nonce: '3c2f1a00-1111-4222-8333-444455556666',
    ...overrides,
  };
}

async function main() {
  // ---- (A) strategy unit tests (circuit policy, WIRING-TRACE.md) --------
  // Policy: self < 30 -> FORTIFY; else opp > 0 -> EXTRACT 10; else HOLD.
  check(
    'strategy: early turn, 95/105 → EXTRACT 10',
    JSON.stringify(decideSteal({ selfBalance: '95', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, 3)) ===
      JSON.stringify({ type: 'EXTRACT', amount: 10 }),
  );
  check(
    'strategy: opp balance 0 → HOLD',
    decideSteal({ selfBalance: '100', opponentBalance: '0', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, 5).type === 'HOLD',
  );
  check(
    'strategy: self low (25/105) → FORTIFY',
    decideSteal({ selfBalance: '25', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, 5).type === 'FORTIFY',
  );
  check(
    'strategy: self low (3/5), behind → FORTIFY (self-balance rule, opp irrelevant)',
    decideSteal({ selfBalance: '3', opponentBalance: '5', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: 5 }, 5).type === 'FORTIFY',
  );
  check(
    'strategy: self at boundary 30/105 → EXTRACT 10 (30 is NOT < 30)',
    JSON.stringify(decideSteal({ selfBalance: '30', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, 5)) ===
      JSON.stringify({ type: 'EXTRACT', amount: 10 }),
  );
  check(
    'strategy: self 29/105 → FORTIFY (29 < 30)',
    decideSteal({ selfBalance: '29', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, 5).type === 'FORTIFY',
  );
  check(
    'strategy: self low + opp broke (25/0) → FORTIFY (circuit fortifies on self alone)',
    decideSteal({ selfBalance: '25', opponentBalance: '0', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, 5).type === 'FORTIFY',
  );
  check(
    'strategy: opp 4 → EXTRACT 10 (amount is the fixed sp0, NOT capped by opp balance)',
    JSON.stringify(decideSteal({ selfBalance: '95', opponentBalance: '4', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, 3)) ===
      JSON.stringify({ type: 'EXTRACT', amount: 10 }),
  );
  check(
    'strategy: opp fortified (105, fortified turn 3) → EXTRACT 10 (fortification is NOT a circuit policy input)',
    JSON.stringify(decideSteal({ selfBalance: '95', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: 3 }, 3)) ===
      JSON.stringify({ type: 'EXTRACT', amount: 10 }),
  );
  check(
    'strategy: late turn 19, ahead (130/90) → EXTRACT 10 (turn is NOT a circuit policy input)',
    JSON.stringify(decideSteal({ selfBalance: '130', opponentBalance: '90', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, 19)) ===
      JSON.stringify({ type: 'EXTRACT', amount: 10 }),
  );
  check(
    'strategy: late turn 19, behind (90/130) → EXTRACT 10',
    JSON.stringify(decideSteal({ selfBalance: '90', opponentBalance: '130', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, 19)) ===
      JSON.stringify({ type: 'EXTRACT', amount: 10 }),
  );
  check(
    'strategy: HOLD/FORTIFY carry no amount field',
    !('amount' in decideSteal({ selfBalance: '100', opponentBalance: '0', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, 5)) &&
    !('amount' in decideSteal({ selfBalance: '25', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, 5)),
  );
  check(
    'strategy: POLICY thresholds match prove-steal STRATEGY_PARAMS',
    POLICY.extractAmount === Number(STRATEGY_PARAMS[0]) &&
    POLICY.fortifyBelow === Number(STRATEGY_PARAMS[1]) &&
    POLICY.extractAbove === Number(STRATEGY_PARAMS[2]) &&
    STRATEGY_PARAMS[3] === '0' &&
    STRATEGY_PARAMS.slice(4).every((x) => x === '0'),
  );
  check(
    'strategy: fractional balance (95.5) → HOLD (safe-integer domain)',
    decideSteal({ selfBalance: '95.5', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, 3).type === 'HOLD',
  );
  check(
    'strategy: fractional turn (3.5) → HOLD',
    decideSteal({ selfBalance: '95', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, 3.5).type === 'HOLD',
  );
  check(
    'strategy: negative balance → HOLD',
    decideSteal({ selfBalance: '-5', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, 3).type === 'HOLD',
  );
  check(
    'strategy: turn 0 and 21 → HOLD',
    decideSteal({ selfBalance: '95', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, 0).type === 'HOLD' &&
    decideSteal({ selfBalance: '95', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, 21).type === 'HOLD',
  );

  // ---- (C) proof generation SUCCEEDS + verifies (circuit SOLVED) ---------
  let proved = null;
  try {
    proved = await generatePolicyProof({
      matchId: '9f4e1b2a-1111-4222-8333-444455556666',
      turn: 3,
      state: { selfBalance: '95', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
      action: { type: 'EXTRACT', amount: 10 },
    });
    check('prove-steal: generates a proof for a valid EXTRACT turn', !!proved?.proof && Array.isArray(proved?.publicSignals) && proved.publicSignals.length === 9);
  } catch (e) {
    check('prove-steal: generates a proof for a valid EXTRACT turn', false, String(e.message || e).slice(0, 200));
  }
  if (proved) {
    const ok = await verifyPolicyProof(proved.proof, proved.publicSignals);
    check('prove-steal: proof VERIFIES against circuit-steal/vk.json (groth16.verify=true)', ok === true);
    const ps = proved.publicSignals;
    check(
      'prove-steal: public signals match the turn (matchId/turn/balances/action/amount/version)',
      ps[2] === encodeMatchId('9f4e1b2a-1111-4222-8333-444455556666') &&
      ps[3] === '3' && ps[4] === '95' && ps[5] === '105' &&
      ps[6] === '2' && ps[7] === '10' && ps[8] === '1',
      `ps=${JSON.stringify(ps)}`,
    );
    // The gap that let the bleed ship: the old harness never asserted
    // the commitment. The platform checks publicSignals[1] against the
    // REGISTERED commitment (dashboard); a random salt made every proof
    // diverge from it (7× proof_failure −2). This must never regress.
    check(
      'prove-steal: publicSignals[1] (commitment) equals the REGISTERED commitment (Poseidon, salt=1)',
      ps[1] === REGISTERED_COMMITMENT,
      `ps[1]=${ps[1]} registered=${REGISTERED_COMMITMENT}`,
    );
  } else {
    check('prove-steal: proof VERIFIES against circuit-steal/vk.json', false, 'no proof generated');
    check('prove-steal: public signals match the turn', false, 'no proof generated');
  }
  // FORTIFY turn also proves (self < 30).
  try {
    const fort = await generatePolicyProof({
      matchId: '9f4e1b2a-1111-4222-8333-444455556666',
      turn: 4,
      state: { selfBalance: '25', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
      action: { type: 'FORTIFY' },
    });
    const ok = await verifyPolicyProof(fort.proof, fort.publicSignals);
    check('prove-steal: FORTIFY turn proof verifies', ok === true && fort.publicSignals[6] === '1' && fort.publicSignals[7] === '0');
  } catch (e) {
    check('prove-steal: FORTIFY turn proof verifies', false, String(e.message || e).slice(0, 200));
  }
  // HOLD turn also proves (opp 0).
  try {
    const hold = await generatePolicyProof({
      matchId: '9f4e1b2a-1111-4222-8333-444455556666',
      turn: 5,
      state: { selfBalance: '100', opponentBalance: '0', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
      action: { type: 'HOLD' },
    });
    const ok = await verifyPolicyProof(hold.proof, hold.publicSignals);
    check('prove-steal: HOLD turn proof verifies', ok === true && hold.publicSignals[6] === '0' && hold.publicSignals[7] === '0');
  } catch (e) {
    check('prove-steal: HOLD turn proof verifies', false, String(e.message || e).slice(0, 200));
  }
  // A WRONG action (not the circuit-computed one) must still fail:
  // EXTRACT when the circuit computes FORTIFY (self 25 < 30).
  // It now throws a clear "policy mismatch" error (defense-in-depth
  // validation in generatePolicyProof) instead of a circuit assert.
  try {
    await generatePolicyProof({
      matchId: '9f4e1b2a-1111-4222-8333-444455556666',
      turn: 6,
      state: { selfBalance: '25', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
      action: { type: 'EXTRACT', amount: 10 },
    });
    check('prove-steal: wrong action (EXTRACT when circuit says FORTIFY) throws', false, 'unexpectedly succeeded');
  } catch (e) {
    check('prove-steal: wrong action (EXTRACT when circuit says FORTIFY) throws', /policy mismatch/.test(String(e.message || e)), String(e.message || e).slice(0, 120));
  }
  // Invalid inputs are rejected explicitly (Codex review round 2, MINOR):
  // turn 0 + HOLD must throw a validation error, NOT pass the comparison
  // and fail at the circuit assert.
  try {
    await generatePolicyProof({
      matchId: '9f4e1b2a-1111-4222-8333-444455556666',
      turn: 0,
      state: { selfBalance: '0', opponentBalance: '1', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
      action: { type: 'HOLD' },
    });
    check('prove-steal: turn 0 + HOLD throws a validation error', false, 'unexpectedly succeeded');
  } catch (e) {
    check('prove-steal: turn 0 + HOLD throws a validation error', /turn out of range/.test(String(e.message || e)), String(e.message || e).slice(0, 120));
  }
  try {
    await generatePolicyProof({
      matchId: '9f4e1b2a-1111-4222-8333-444455556666',
      turn: 3,
      state: { selfBalance: '95.5', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
      action: { type: 'HOLD' },
    });
    check('prove-steal: fractional balance throws a validation error', false, 'unexpectedly succeeded');
  } catch (e) {
    check('prove-steal: fractional balance throws a validation error', /invalid input selfBalance/.test(String(e.message || e)), String(e.message || e).slice(0, 120));
  }

  // ---- (B) HTTP endpoint tests -------------------------------------------
  const child = spawn(process.execPath, [path.join(__dirname, 'server.mjs')], {
    env: {
      ...process.env,
      PORT: String(PORT),
      AGENT_GAMES_HMAC_SECRET: GK_SECRET,
      STEAL_HMAC_SECRET: STEAL_SECRET,
      STATE_PATH,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverLog = '';
  child.stdout.on('data', (d) => (serverLog += d));
  child.stderr.on('data', (d) => (serverLog += d));
  try {
    let ready = false;
    for (let i = 0; i < 50 && !ready; i++) {
      try {
        const r = await request({ method: 'GET', path: '/health', sign: false });
        ready = r.status === 200;
      } catch {
        await new Promise((r) => setTimeout(r, 100));
      }
    }
    check('server starts and answers GET /health', ready, serverLog.slice(-300));
    if (ready) {
      const h = await request({ method: 'GET', path: '/health', sign: false });
      const hj = parse(h);
      check(
        'health reports dual service + steal strategy',
        hj?.service === 'proof-gatekeeper+steal-the-vfy' && hj?.steal === 'optimal-strategy-v1',
        h.body.slice(0, 160),
      );
    }

    // Preflight with the STEAL secret → 200, signed with the STEAL secret.
    let r = await request({ body: { type: 'agent-games.preflight.v1' }, secret: STEAL_SECRET });
    let j = parse(r);
    check(
      'preflight (Steal secret) → 200 ok + signed with Steal secret',
      r.status === 200 && j?.ok === true && j?.protocolVersion === 'v1' && sigValid(r, STEAL_SECRET),
      `status=${r.status} body=${r.body.slice(0, 120)}`,
    );
    // Preflight with the Gatekeeper secret → 200, signed with the GK secret.
    r = await request({ body: { type: 'agent-games.preflight.v1' }, secret: GK_SECRET });
    j = parse(r);
    check(
      'preflight (Gatekeeper secret) → 200 ok + signed with Gatekeeper secret',
      r.status === 200 && j?.ok === true && sigValid(r, GK_SECRET) && !sigValid(r, STEAL_SECRET),
      `status=${r.status}`,
    );
    // Preflight bad/missing signature → 401.
    r = await request({ body: { type: 'agent-games.preflight.v1' }, secret: 'wrong-secret' });
    check('preflight bad signature → 401', r.status === 401, `status=${r.status}`);
    r = await request({ body: { type: 'agent-games.preflight.v1' }, sign: false });
    check('preflight missing signature → 401', r.status === 401, `status=${r.status}`);

    // Valid Steal turn (EXTRACT scenario, 95/105) → 200, EXTRACT 10 +
    // a VERIFYING policyProof, signed with the Steal secret, echoes
    // matchId/turn, has idempotencyKey.
    const env1 = turnEnv();
    r = await request({ body: env1, secret: STEAL_SECRET });
    j = parse(r);
    let proofOk = false;
    let psOk = false;
    if (j?.policyProof?.proof && Array.isArray(j.policyProof.public_signals)) {
      proofOk = await verifyPolicyProof(j.policyProof.proof, j.policyProof.public_signals);
      const ps = j.policyProof.public_signals;
      psOk =
        ps.length === 9 &&
        ps[2] === encodeMatchId(env1.matchId) &&
        ps[3] === '3' && ps[4] === '95' && ps[5] === '105' &&
        ps[6] === '2' && ps[7] === '10' && ps[8] === '1' &&
        j.policyProof.circuitVersion === 'v1';
    }
    check(
      'valid Steal turn → 200 EXTRACT 10 + verifying policyProof, signed (Steal), echoes matchId/turn',
      r.status === 200 &&
        j?.matchId === env1.matchId &&
        j?.turn === 3 &&
        j?.action?.type === 'EXTRACT' &&
        j?.action?.amount === 10 &&
        proofOk && psOk &&
        typeof j?.idempotencyKey === 'string' &&
        j.idempotencyKey.length > 0 &&
        typeof j?.agentTimestamp === 'string' &&
        sigValid(r, STEAL_SECRET),
      `status=${r.status} proofOk=${proofOk} psOk=${psOk} body=${r.body.slice(0, 220)}`,
    );

    // Replay same (matchId, turn) → identical response (idempotent).
    const r2 = await request({ body: turnEnv(), secret: STEAL_SECRET });
    check(
      'replay same (matchId, turn) → identical response',
      r2.status === 200 && r2.body === r.body,
      `status=${r2.status}`,
    );

    // Concurrent replay → both get the same response.
    const envC = turnEnv({ matchId: '9f4e1b2a-2222-4222-8333-444455556666', turn: 4 });
    const [c1, c2] = await Promise.all([
      request({ body: envC, secret: STEAL_SECRET }),
      request({ body: envC, secret: STEAL_SECRET }),
    ]);
    check(
      'concurrent replay → both 200 + identical body',
      c1.status === 200 && c2.status === 200 && c1.body === c2.body,
      `c1=${c1.status} c2=${c2.status}`,
    );

    // Malformed turn (missing state) → HOLD, no proof, 200, signed.
    r = await request({ body: turnEnv({ matchId: '9f4e1b2a-3333-4222-8333-444455556666', state: undefined }), secret: STEAL_SECRET });
    // (turnEnv spread with state: undefined keeps the key; delete it explicitly.)
    if (r.status !== 200) {
      const envM = turnEnv({ matchId: '9f4e1b2a-3333-4222-8333-444455556666' });
      delete envM.state;
      r = await request({ body: envM, secret: STEAL_SECRET });
    }
    j = parse(r);
    check(
      'malformed turn (no state) → 200 HOLD, no policyProof, signed',
      r.status === 200 && j?.action?.type === 'HOLD' && !('policyProof' in j) && sigValid(r, STEAL_SECRET),
      `status=${r.status} body=${r.body.slice(0, 160)}`,
    );

    // Wrong commitment hash → HOLD, no proof.
    r = await request({
      body: turnEnv({
        matchId: '9f4e1b2a-4444-4222-8333-444455556666',
        strategyCommitment: { hash: '0x0000000000000000000000000000000000000000000000000000000000000000' },
      }),
      secret: STEAL_SECRET,
    });
    j = parse(r);
    check(
      'wrong commitment hash → 200 HOLD, no policyProof',
      r.status === 200 && j?.action?.type === 'HOLD' && !('policyProof' in j),
      `status=${r.status} body=${r.body.slice(0, 160)}`,
    );

    // Turn out of range (0 and 21) → HOLD.
    for (const badTurn of [0, 21]) {
      r = await request({
        body: turnEnv({ matchId: `9f4e1b2a-5555-4222-8333-44445555666${badTurn}`, turn: badTurn }),
        secret: STEAL_SECRET,
      });
      j = parse(r);
      check(
        `turn ${badTurn} out of range → 200 HOLD`,
        r.status === 200 && j?.action?.type === 'HOLD' && !('policyProof' in j),
        `status=${r.status}`,
      );
    }

    // Bad / missing HMAC on a Steal turn → 401.
    r = await request({ body: turnEnv({ matchId: '9f4e1b2a-6666-4222-8333-444455556666' }), secret: 'wrong-secret' });
    check('Steal turn bad signature → 401', r.status === 401, `status=${r.status}`);
    r = await request({ body: turnEnv({ matchId: '9f4e1b2a-7777-4222-8333-444455556666' }), sign: false });
    check('Steal turn missing signature → 401', r.status === 401, `status=${r.status}`);

    // Unknown envelope type → 400.
    r = await request({ body: { type: 'agent-games.unknown.v1' }, secret: STEAL_SECRET });
    check('unknown envelope type → 400', r.status === 400, `status=${r.status}`);

    // Malformed JSON (valid sig) → 400.
    r = await request({ rawBody: '{not json', secret: STEAL_SECRET });
    check('malformed JSON (valid sig) → 400', r.status === 400, `status=${r.status}`);

    // Fractional balance → invalid (uncached HOLD, not persisted).
    // (Codex review round 2, MAJOR fix.)
    r = await request({
      body: turnEnv({
        matchId: '9f4e1b2a-aaaa-4222-8333-444455556666',
        state: { selfBalance: '95.5', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
      }),
      secret: STEAL_SECRET,
    });
    j = parse(r);
    check(
      'fractional balance → 200 HOLD, no policyProof (uncached)',
      r.status === 200 && j?.action?.type === 'HOLD' && !('policyProof' in j),
      `status=${r.status}`,
    );

    // Fractional turn → invalid (uncached HOLD, not persisted, must not
    // poison the corresponding integer turn).
    // (Codex review round 3, MINOR fix.) Distinct nonces prove the
    // legitimate turn is processed fresh, not replayed from the
    // fractional turn's record.
    r = await request({
      body: turnEnv({
        matchId: '9f4e1b2a-bbbb-4222-8333-444455556666',
        turn: 1.5,
        nonce: 'frac-nonce-1',
      }),
      secret: STEAL_SECRET,
    });
    j = parse(r);
    const fracTurnOk =
      r.status === 200 && j?.action?.type === 'HOLD' && !('policyProof' in j);
    // Now the legitimate turn 1 for the same match must be processed
    // fresh (its own nonce in the response) with its strategy action
    // (95/105 → EXTRACT 10) + a verifying proof.
    r = await request({
      body: turnEnv({
        matchId: '9f4e1b2a-bbbb-4222-8333-444455556666',
        turn: 1,
        nonce: 'legit-nonce-1',
      }),
      secret: STEAL_SECRET,
    });
    j = parse(r);
    let legitProofOk = false;
    if (j?.policyProof?.proof && Array.isArray(j.policyProof.public_signals)) {
      legitProofOk = await verifyPolicyProof(j.policyProof.proof, j.policyProof.public_signals);
    }
    const legitTurnOk =
      r.status === 200 &&
      j?.turn === 1 &&
      j?.action?.type === 'EXTRACT' &&
      j?.action?.amount === 10 &&
      j?.idempotencyKey === 'legit-nonce-1' &&
      legitProofOk;
    check(
      'fractional turn 1.5 → uncached HOLD; legitimate turn 1 after it → EXTRACT 10 + verifying proof (own nonce)',
      fracTurnOk && legitTurnOk,
      `frac=${fracTurnOk} legit=${legitTurnOk} key=${j?.idempotencyKey} proofOk=${legitProofOk}`,
    );

    // Cross-agent: a Steal turn signed with the Gatekeeper secret → 401.
    // (Codex review round 1, MAJOR fix.)
    r = await request({
      body: turnEnv({ matchId: '9f4e1b2a-8888-4222-8333-444455556666' }),
      secret: GK_SECRET,
    });
    check('Steal turn signed with Gatekeeper secret → 401 (bad_agent)', r.status === 401, `status=${r.status}`);

    // No-poisoning: an invalid turn for (matchId, turn) must NOT block a
    // later VALID turn for the same (matchId, turn).
    // (Codex review round 1, MAJOR fix.)
    const poisonId = '9f4e1b2a-9999-4222-8333-444455556666';
    const badEnv = turnEnv({ matchId: poisonId });
    delete badEnv.state;
    r = await request({ body: badEnv, secret: STEAL_SECRET });
    const badOk = r.status === 200 && parse(r)?.action?.type === 'HOLD';
    r = await request({ body: turnEnv({ matchId: poisonId }), secret: STEAL_SECRET });
    const goodJ = parse(r);
    let goodProofOk = false;
    if (goodJ?.policyProof?.proof && Array.isArray(goodJ.policyProof.public_signals)) {
      goodProofOk = await verifyPolicyProof(goodJ.policyProof.proof, goodJ.policyProof.public_signals);
    }
    const goodOk =
      r.status === 200 &&
      goodJ?.action?.type === 'EXTRACT' &&
      goodJ?.action?.amount === 10 &&
      goodProofOk &&
      sigValid(r, STEAL_SECRET);
    check(
      'invalid turn then valid turn (same matchId/turn) → valid turn processed (EXTRACT 10 + proof), not poisoned',
      badOk && goodOk,
      `bad=${badOk} good=${goodOk}`,
    );

    // State persisted: ONLY valid turns are recorded. Invalid turns
    // (malformed, wrong commitment, out-of-range) must NOT be persisted
    // (Codex review round 1, MAJOR fix) — a later valid turn for the
    // same (matchId, turn) must still be processed fresh.
    try {
      const saved = JSON.parse(fs.readFileSync(STATE_PATH, 'utf8'));
      const ids = saved.stealMatches ? Object.keys(saved.stealMatches) : [];
      const hasValid1111 = ids.includes('9f4e1b2a-1111-4222-8333-444455556666');
      const hasValid2222 = ids.includes('9f4e1b2a-2222-4222-8333-444455556666');
      const hasValid9999 = ids.includes('9f4e1b2a-9999-4222-8333-444455556666');
      const hasValidBbbb = ids.includes('9f4e1b2a-bbbb-4222-8333-444455556666');
      const hasInvalid3333 = ids.includes('9f4e1b2a-3333-4222-8333-444455556666');
      const hasInvalid4444 = ids.includes('9f4e1b2a-4444-4222-8333-444455556666');
      const hasInvalid8888 = ids.includes('9f4e1b2a-8888-4222-8333-444455556666');
      const hasInvalidAaaa = ids.includes('9f4e1b2a-aaaa-4222-8333-444455556666');
      // Valid stored turns must carry a verifying proof.
      let storedProofsOk = true;
      for (const id of ['9f4e1b2a-1111-4222-8333-444455556666', '9f4e1b2a-2222-4222-8333-444455556666', '9f4e1b2a-9999-4222-8333-444455556666', '9f4e1b2a-bbbb-4222-8333-444455556666']) {
        const turns = saved.stealMatches[id] || {};
        for (const tk of Object.keys(turns)) {
          const rec = turns[tk];
          if (!rec.policyProof?.proof || !Array.isArray(rec.policyProof.public_signals)) { storedProofsOk = false; break; }
          if (!(await verifyPolicyProof(rec.policyProof.proof, rec.policyProof.public_signals))) { storedProofsOk = false; break; }
        }
      }
      check(
        'state.json persisted ONLY valid stealMatches (invalid turns not stored) + stored turns carry verifying proofs',
        ids.length === 4 && hasValid1111 && hasValid2222 && hasValid9999 && hasValidBbbb &&
          !hasInvalid3333 && !hasInvalid4444 && !hasInvalid8888 && !hasInvalidAaaa &&
          storedProofsOk,
        `matches=${ids.join(',')} storedProofsOk=${storedProofsOk}`,
      );
    } catch (e) {
      check('state.json persisted ONLY valid stealMatches', false, e.message);
    }
  } finally {
    try {
      child.kill('SIGTERM');
    } catch {}
  }

  console.log(results.join('\n'));
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => {
  console.error('HARNESS CRASH:', e);
  process.exit(1);
});
