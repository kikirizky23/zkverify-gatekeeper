// harness-steal.mjs — local test harness for the Steal the VFY branch.
// Spawns steal-v2/server.mjs on a test port with DUMMY secrets, then:
//  (A) unit-tests the "Optimal Strategy" (strategy.mjs) decision rules;
//  (B) sends signed Steal turn envelopes and asserts the HTTP behaviour
//      (routing, HMAC, fail-closed HOLD, idempotency, shape);
//  (C) confirms the vfy-policy proof generation fails (circuit blocker)
//      and that the server falls back to HOLD with no proof (never a
//      crash, never a fabricated proof).
// Exit 0 = all pass, 1 = any failure. No network beyond localhost.
// Usage: node harness-steal.mjs
// NOTE: because the circuit is BLOCKED (prove-steal.mjs CIRCUIT-BLOCKER),
// a valid turn is expected to return HOLD with NO policyProof. That is
// the intended fail-closed behaviour. If the circuit is ever resolved,
// the "valid turn" expectations below must be updated to expect the
// strategy action + a verifying proof.
import http from 'node:http';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { decideSteal } from './strategy.mjs';
import { generatePolicyProof } from './prove-steal.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = 3105;
const GK_SECRET = 'dummy-test-secret-NEVER-USE-IN-PRODUCTION';
const STEAL_SECRET = 'dummy-steal-secret-NEVER-USE-IN-PRODUCTION';
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'steal-harness-'));
const STATE_PATH = path.join(TMP, 'state.json');
const COMMITMENT =
  '0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047';

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
  // ---- (A) strategy unit tests -------------------------------------------
  check(
    'strategy: early turn, opp not fortified → EXTRACT 10',
    JSON.stringify(decideSteal({ selfBalance: '95', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, 3)) ===
      JSON.stringify({ type: 'EXTRACT', amount: 10 }),
  );
  check(
    'strategy: opp balance 0 → HOLD',
    decideSteal({ selfBalance: '100', opponentBalance: '0', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, 5).type === 'HOLD',
  );
  check(
    'strategy: opp fortified + low balance (5) → extract gain 0, ahead → FORTIFY',
    decideSteal({ selfBalance: '120', opponentBalance: '5', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: 5 }, 5).type === 'FORTIFY',
  );
  check(
    'strategy: opp fortified + low balance (5), behind → HOLD',
    decideSteal({ selfBalance: '3', opponentBalance: '5', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: 5 }, 5).type === 'HOLD',
  );
  check(
    'strategy: late turn 19, ahead → FORTIFY',
    decideSteal({ selfBalance: '130', opponentBalance: '90', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, 19).type === 'FORTIFY',
  );
  check(
    'strategy: late turn 19, behind → EXTRACT 10',
    JSON.stringify(decideSteal({ selfBalance: '90', opponentBalance: '130', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, 19)) ===
      JSON.stringify({ type: 'EXTRACT', amount: 10 }),
  );
  check(
    'strategy: mid game, ahead by 25 (turn 12) → FORTIFY',
    decideSteal({ selfBalance: '125', opponentBalance: '100', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, 12).type === 'FORTIFY',
  );
  check(
    'strategy: EXTRACT amount capped by opp balance (opp 4) → EXTRACT 4',
    JSON.stringify(decideSteal({ selfBalance: '95', opponentBalance: '4', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, 3)) ===
      JSON.stringify({ type: 'EXTRACT', amount: 4 }),
  );
  check(
    'strategy: opp fortified, opp 105 → EXTRACT 10 (gain 4, still best)',
    JSON.stringify(decideSteal({ selfBalance: '95', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: 3 }, 3)) ===
      JSON.stringify({ type: 'EXTRACT', amount: 10 }),
  );
  check(
    'strategy: HOLD/FORTIFY carry no amount field',
    !('amount' in decideSteal({ selfBalance: '100', opponentBalance: '0', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, 5)),
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

  // ---- (C) proof generation fails (circuit blocker) ----------------------
  let proveErr = '';
  try {
    await generatePolicyProof({
      matchId: '9f4e1b2a-1111-4222-8333-444455556666',
      turn: 3,
      state: { selfBalance: '95', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
      action: { type: 'EXTRACT', amount: 5 },
    });
    check('prove-steal: expected to throw (circuit blocker)', false, 'unexpectedly succeeded');
  } catch (e) {
    proveErr = String(e.message || e);
    check(
      'prove-steal: throws at template assert (circuit blocker, expected)',
      /Assert Failed.*line: 72/.test(proveErr),
      proveErr.slice(0, 120),
    );
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

    // Valid Steal turn (EXTRACT scenario) → 200, HOLD + NO proof
    // (circuit blocker: fail-closed), no amount field, signed with
    // the Steal secret, echoes matchId/turn, has idempotencyKey.
    const env1 = turnEnv();
    r = await request({ body: env1, secret: STEAL_SECRET });
    j = parse(r);
    check(
      'valid Steal turn → 200 HOLD, no policyProof, no amount, signed (Steal), echoes matchId/turn',
      r.status === 200 &&
        j?.matchId === env1.matchId &&
        j?.turn === 3 &&
        j?.action?.type === 'HOLD' &&
        !('amount' in (j?.action || {})) &&
        !('policyProof' in j) &&
        typeof j?.idempotencyKey === 'string' &&
        j.idempotencyKey.length > 0 &&
        typeof j?.agentTimestamp === 'string' &&
        sigValid(r, STEAL_SECRET),
      `status=${r.status} body=${r.body.slice(0, 220)}`,
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
    // fresh (its own nonce in the response), not replayed.
    r = await request({
      body: turnEnv({
        matchId: '9f4e1b2a-bbbb-4222-8333-444455556666',
        turn: 1,
        nonce: 'legit-nonce-1',
      }),
      secret: STEAL_SECRET,
    });
    j = parse(r);
    const legitTurnOk =
      r.status === 200 &&
      j?.turn === 1 &&
      j?.action?.type === 'HOLD' &&
      j?.idempotencyKey === 'legit-nonce-1' &&
      !('policyProof' in j);
    check(
      'fractional turn 1.5 → uncached HOLD; legitimate turn 1 after it → processed fresh (own nonce)',
      fracTurnOk && legitTurnOk,
      `frac=${fracTurnOk} legit=${legitTurnOk} key=${j?.idempotencyKey}`,
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
    const goodOk =
      r.status === 200 &&
      parse(r)?.action?.type === 'HOLD' &&
      !('policyProof' in (parse(r) || {})) &&
      sigValid(r, STEAL_SECRET);
    check(
      'invalid turn then valid turn (same matchId/turn) → valid turn processed, not poisoned',
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
      check(
        'state.json persisted ONLY valid stealMatches (invalid turns not stored)',
        ids.length === 4 && hasValid1111 && hasValid2222 && hasValid9999 && hasValidBbbb &&
          !hasInvalid3333 && !hasInvalid4444 && !hasInvalid8888 && !hasInvalidAaaa,
        `matches=${ids.join(',')}`,
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
