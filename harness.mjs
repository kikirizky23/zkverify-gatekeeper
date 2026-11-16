// harness.mjs — local test harness for the Gatekeeper agent (GROTH16 pass).
// Spawns server.mjs on a test port with a DUMMY secret, sends a signed
// preflight + one task of EACH of the 7 trap types (built from the spec
// §02 example envelope) + edge cases, and asserts decisions, Groth16 proofs
// (present + verify on provable tasks, absent on VK_SUBSTITUTION), the
// proving-failure fallback (logic-only, correct decision), and that every
// response carries a valid x-agent-games-signature over the raw body.
// Exit 0 = all pass, 1 = any failure. No network beyond localhost.
// Usage: node harness.mjs
import http from 'node:http';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as snarkjs from 'snarkjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = 3101;
const SECRET = 'dummy-test-secret-NEVER-USE-IN-PRODUCTION';
const STEAL_SECRET = 'dummy-steal-secret-NEVER-USE-IN-PRODUCTION';
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'gk-harness-'));
const STATE_PATH = path.join(TMP, 'state.json');
// Verification key for the circuit (public protocol artifact).
const VK_JSON = JSON.parse(fs.readFileSync(path.join(__dirname, 'circuit', 'vk.json'), 'utf8'));

let passed = 0;
let failed = 0;
const results = [];
function check(name, ok, detail = '') {
  results.push(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
  if (ok) passed++;
  else failed++;
}

// ---- client helpers ------------------------------------------------------
function hmacHex(body) {
  return crypto.createHmac('sha256', SECRET).update(body).digest('hex');
}
// port defaults to the main server; pass a different port for the
// failure-injection server (Step 4 case).
function request({ method = 'POST', path = '/agent', body, sign = true, rawBody, port = PORT }) {
  return new Promise((resolve, reject) => {
    const data = rawBody !== undefined ? rawBody : body !== undefined ? JSON.stringify(body) : '';
    const headers = { 'content-type': 'application/json' };
    if (sign) headers['x-agent-games-signature'] = hmacHex(data);
    const req = http.request(
      { host: '127.0.0.1', port, path, method, headers },
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
async function verifyProof(j) {
  if (!j || !j.proof || !Array.isArray(j.public_signals) || j.public_signals.length !== 13) {
    return false;
  }
  try {
    return await snarkjs.groth16.verify(VK_JSON, j.public_signals, j.proof);
  } catch {
    return false;
  }
}
function sigValid(res) {
  const given = res.headers['x-agent-games-signature'];
  if (!given) return false;
  const expected = hmacHex(res.body);
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

// ---- envelope builders (from spec §02 example) ---------------------------
const ADDR = '0xDe4200000000000000000000000000000000009f01';
// Real registered vk_hash (plan §2.4) — the harness must use it so the
// circuit's registeredVkHash == proofVkHash check passes and proving
// succeeds. (A dummy VK would make every proof fail the circuit assert
// and fall back to logic-only.)
const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
let n = 0;
function proofTx() {
  n += 1;
  return '0xa8' + String(n).padStart(62, '0');
}
function baseInput(overrides = {}) {
  return {
    registered_vk: VK,
    proof_vk: VK,
    minimum: '1000',
    public_balance: '1460',
    expiry_block: 8430000,
    current_block: 8420000,
    recipient: ADDR,
    condition_recipient: ADDR,
    amount: '500',
    max_transfer: '1000',
    proof_tx: proofTx(),
    ...overrides,
  };
}
function task(taskId, input, extra = {}) {
  const now = new Date();
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: taskId,
    mode: 'practice',
    issued_at: now.toISOString(),
    deadline_at: new Date(now.getTime() + 60_000).toISOString(),
    input,
    ...extra,
  };
}

// ---- main ------------------------------------------------------------------
async function main() {
  const child = spawn(process.execPath, [path.join(__dirname, 'server.mjs')], {
    env: {
      ...process.env,
      PORT: String(PORT),
      AGENT_GAMES_HMAC_SECRET: SECRET,
      STEAL_HMAC_SECRET: STEAL_SECRET,
      STATE_PATH,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverLog = '';
  child.stdout.on('data', (d) => (serverLog += d));
  child.stderr.on('data', (d) => (serverLog += d));

  const cleanup = () => {
    try {
      child.kill('SIGTERM');
    } catch {}
    try {
      fs.rmSync(TMP, { recursive: true, force: true });
    } catch {}
  };

  try {
    // wait for listen
    let ready = false;
    for (let i = 0; i < 50 && !ready; i++) {
      try {
        const r = await request({ method: 'GET', path: '/health', sign: false });
        ready = r.status === 200;
      } catch {
        await new Promise((r) => setTimeout(r, 100));
      }
    }
    check('server starts and answers GET /health', ready, ready ? '' : serverLog.slice(-500));

    // 1. preflight, correctly signed
    {
      const r = await request({
        body: {
          type: 'agent-games.preflight.v1',
          agent_id: 'agt_test',
          issued_at: new Date().toISOString(),
          nonce: 'abc123',
        },
      });
      const j = parse(r);
      check(
        'preflight signed → 200 {ok:true, protocolVersion:"v1"} + valid sig',
        r.status === 200 && j?.ok === true && j?.protocolVersion === 'v1' && sigValid(r),
        `status=${r.status} body=${r.body}`,
      );
    }
    // 2. preflight, bad signature → 401
    {
      const r = await request({
        body: { type: 'agent-games.preflight.v1' },
        sign: false,
      });
      // send with a wrong signature explicitly
      const bad = await new Promise((resolve, reject) => {
        const data = JSON.stringify({ type: 'agent-games.preflight.v1' });
        const req = http.request(
          {
            host: '127.0.0.1',
            port: PORT,
            path: '/agent',
            method: 'POST',
            headers: {
              'content-type': 'application/json',
              'x-agent-games-signature': 'deadbeef',
            },
          },
          (res) => {
            const c = [];
            res.on('data', (x) => c.push(x));
            res.on('end', () =>
              resolve({ status: res.statusCode, body: Buffer.concat(c).toString() }),
            );
          },
        );
        req.on('error', reject);
        req.end(data);
      });
      check('preflight bad signature → 401', bad.status === 401, `status=${bad.status}`);
      check('preflight missing signature → 401', r.status === 401, `status=${r.status}`);
    }

    // 3. VALID_CONDITION → APPROVE + Groth16 proof (task_id gk_24_valid
    // exercises the decimal taskId encoding: publicSignals[12] == "24").
    const validTx = proofTx();
    let validInput;
    let validProofJson = '';
    let validPubJson = '';
    let validMs = 0;
    {
      validInput = baseInput({ proof_tx: validTx });
      const t0 = Date.now();
      const r = await request({ body: task('gk_24_valid', validInput) });
      validMs = Date.now() - t0;
      const j = parse(r);
      const proofOk =
        r.status === 200 &&
        j?.decision === 'APPROVE' &&
        j?.reason_code === 'VALID_CONDITION' &&
        j?.proof_tx === validTx &&
        'proof' in j &&
        Array.isArray(j.public_signals) &&
        j.public_signals.length === 13 &&
        j.public_signals[11] === '1' &&
        j.public_signals[12] === '24' &&
        sigValid(r);
      const verifies = proofOk && (await verifyProof(j));
      validProofJson = JSON.stringify(j?.proof);
      validPubJson = JSON.stringify(j?.public_signals);
      check(
        'VALID_CONDITION → APPROVE + proof (13 pub signals, pub[11]="1", pub[12]="24", verifies, valid sig)',
        proofOk && verifies,
        `status=${r.status} body=${String(r.body).slice(0, 200)}`,
      );
      check('VALID proving wall-clock < 10s', validMs < 10_000, `${validMs}ms`);
    }
    // 4. replay same task_id → same APPROVE + same proof (idempotent, NOT PROOF_REUSED)
    {
      const r = await request({ body: task('gk_24_valid', validInput) });
      const j = parse(r);
      check(
        'replay same task_id → same APPROVE + identical proof (idempotent)',
        r.status === 200 &&
          j?.decision === 'APPROVE' &&
          j?.reason_code === 'VALID_CONDITION' &&
          JSON.stringify(j?.proof) === validProofJson &&
          JSON.stringify(j?.public_signals) === validPubJson,
        `body=${String(r.body).slice(0, 200)}`,
      );
    }
    // 4b. CONCURRENT replay: two identical requests in flight at once must
    // both get the SAME proof-bearing response (the second awaits the
    // first's in-flight prove instead of reading the interim record).
    {
      const input = baseInput();
      const env = task('gk_24_concurrent', input);
      const [r1, r2] = await Promise.all([request({ body: env }), request({ body: env })]);
      const j1 = parse(r1);
      const j2 = parse(r2);
      check(
        'concurrent replay → both APPROVE with identical proof',
        r1.status === 200 &&
          r2.status === 200 &&
          j1?.decision === 'APPROVE' &&
          j2?.decision === 'APPROVE' &&
          'proof' in j1 &&
          'proof' in j2 &&
          JSON.stringify(j1.proof) === JSON.stringify(j2.proof) &&
          JSON.stringify(j1.public_signals) === JSON.stringify(j2.public_signals),
        `r1=${String(r1.body).slice(0, 120)} r2=${String(r2.body).slice(0, 120)}`,
      );
    }
    {
      const r = await request({
        body: task('gk_test_reused', baseInput({ proof_tx: validTx })),
      });
      const j = parse(r);
      check(
        'PROOF_REUSED → REJECT / PROOF_REUSED',
        r.status === 200 && j?.decision === 'REJECT' && j?.reason_code === 'PROOF_REUSED',
        `body=${r.body}`,
      );
    }
    // 6. VK_SUBSTITUTION — correct REJECT, NO proof (by design, plan §6.2)
    {
      const r = await request({
        body: task(
          'gk_test_vk',
          baseInput({ proof_vk: '0x13000000000000000000000000000000000000000000000000000000000000aa' }),
        ),
      });
      const j = parse(r);
      check(
        'VK_SUBSTITUTION → REJECT / VK_SUBSTITUTION, no proof attached (by design)',
        r.status === 200 &&
          j?.decision === 'REJECT' &&
          j?.reason_code === 'VK_SUBSTITUTION' &&
          !('proof' in j) &&
          !('public_signals' in j) &&
          sigValid(r),
        `body=${r.body}`,
      );
    }
    // 7. THRESHOLD_MISMATCH — REJECT, but WITH a valid proof (decision "0")
    {
      const t0 = Date.now();
      const r = await request({
        body: task('gk_test_threshold', baseInput({ public_balance: '900' })),
      });
      const trapMs = Date.now() - t0;
      const j = parse(r);
      const proofOk =
        r.status === 200 &&
        j?.decision === 'REJECT' &&
        j?.reason_code === 'THRESHOLD_MISMATCH' &&
        'proof' in j &&
        Array.isArray(j.public_signals) &&
        j.public_signals.length === 13 &&
        j.public_signals[11] === '0' &&
        sigValid(r);
      const verifies = proofOk && (await verifyProof(j));
      check(
        'THRESHOLD_MISMATCH → REJECT + proof (pub[11]="0", verifies, valid sig)',
        proofOk && verifies,
        `status=${r.status} body=${String(r.body).slice(0, 200)}`,
      );
      check('TRAP proving wall-clock < 10s', trapMs < 10_000, `${trapMs}ms`);
    }
    // 8. EXPIRED_CONDITION
    {
      const r = await request({
        body: task('gk_test_expired', baseInput({ current_block: 8430001 })),
      });
      const j = parse(r);
      check(
        'EXPIRED_CONDITION (current 8430001 > expiry 8430000) → REJECT',
        r.status === 200 && j?.decision === 'REJECT' && j?.reason_code === 'EXPIRED_CONDITION',
        `body=${r.body}`,
      );
    }
    // 9. RECIPIENT_MISMATCH
    {
      const r = await request({
        body: task(
          'gk_test_recipient',
          baseInput({ recipient: '0xDe4200000000000000000000000000000000009f02' }),
        ),
      });
      const j = parse(r);
      check(
        'RECIPIENT_MISMATCH → REJECT / RECIPIENT_MISMATCH',
        r.status === 200 && j?.decision === 'REJECT' && j?.reason_code === 'RECIPIENT_MISMATCH',
        `body=${r.body}`,
      );
    }
    // 10. AMOUNT_OVERFLOW (amount > max_transfer)
    {
      const r = await request({
        body: task('gk_test_amount', baseInput({ amount: '1500' })),
      });
      const j = parse(r);
      check(
        'AMOUNT_OVERFLOW (amount 1500 > max 1000) → REJECT',
        r.status === 200 && j?.decision === 'REJECT' && j?.reason_code === 'AMOUNT_OVERFLOW',
        `body=${r.body}`,
      );
    }
    // 11. AMOUNT_OVERFLOW via balance (amount <= max but > balance)
    {
      const r = await request({
        body: task(
          'gk_test_amount_bal',
          baseInput({ amount: '1200', max_transfer: '1500', public_balance: '1100' }),
        ),
      });
      const j = parse(r);
      check(
        'AMOUNT_OVERFLOW (amount 1200 > balance 1100) → REJECT',
        r.status === 200 && j?.decision === 'REJECT' && j?.reason_code === 'AMOUNT_OVERFLOW',
        `body=${r.body}`,
      );
    }
    // 12. Boundary APPROVE: current == expiry, amount == max, balance == minimum
    {
      const r = await request({
        body: task(
          'gk_test_boundary',
          baseInput({
            current_block: 8430000,
            amount: '1000',
            public_balance: '1000',
          }),
        ),
      });
      const j = parse(r);
      check(
        'boundary (current==expiry, amount==max, balance==minimum) → APPROVE',
        r.status === 200 && j?.decision === 'APPROVE' && j?.reason_code === 'VALID_CONDITION',
        `body=${r.body}`,
      );
    }
    // 13. Unknown type → 400
    {
      const r = await request({ body: { type: 'agent-games.something-else.v1' } });
      check('unknown envelope type → 400', r.status === 400, `status=${r.status}`);
    }
    // 14. Malformed JSON with valid signature → 400
    {
      const raw = '{not json';
      const r = await request({ rawBody: raw, sign: true });
      check('malformed JSON (valid sig) → 400', r.status === 400, `status=${r.status}`);
    }
    // 15. Missing proof_tx but otherwise valid → APPROVE (optional field)
    {
      const input = baseInput();
      delete input.proof_tx;
      const r = await request({ body: task('gk_test_noptx', input) });
      const j = parse(r);
      check(
        'missing proof_tx, otherwise valid → APPROVE (proof_tx optional per spec)',
        r.status === 200 && j?.decision === 'APPROVE' && !('proof_tx' in j),
        `body=${r.body}`,
      );
    }
    // 16. Grossly stale issued_at → REJECT EXPIRED_CONDITION
    {
      const stale = new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString();
      const r = await request({
        body: task('gk_test_stale', baseInput(), { issued_at: stale }),
      });
      const j = parse(r);
      check(
        'stale issued_at (25h ago) → REJECT / EXPIRED_CONDITION',
        r.status === 200 && j?.decision === 'REJECT' && j?.reason_code === 'EXPIRED_CONDITION',
        `body=${r.body}`,
      );
    }
    // 17. State file persisted (proof owners + decisions survive)
    {
      const saved = JSON.parse(fs.readFileSync(STATE_PATH, 'utf8'));
      check(
        'state.json persisted proof owners + decisions (with proof stored)',
        saved.proofOwners?.[validTx] === 'gk_24_valid' &&
          saved.decisions?.['gk_24_valid']?.decision === 'APPROVE' &&
          'proof' in (saved.decisions?.['gk_24_valid'] || {}),
        `owners=${Object.keys(saved.proofOwners || {}).length}`,
      );
    }
    // 18. STATE-SAVE FAILURE — a server whose state file cannot be written
    // must still return the CORRECT logic-only decision (HTTP 200, signed)
    // and must NOT attach a proof (a proof is only sent when durably
    // stored). This covers the first-save-failure path (Codex round 2).
    {
      const SAVE_PORT = PORT + 2;
      const saveChild = spawn(process.execPath, [path.join(__dirname, 'server.mjs')], {
        env: {
          ...process.env,
          PORT: String(SAVE_PORT),
          AGENT_GAMES_HMAC_SECRET: SECRET,
          STEAL_HMAC_SECRET: STEAL_SECRET,
          STATE_PATH: path.join(TMP, 'no-such-dir', 'state.json'),
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let saveLog = '';
      saveChild.stdout.on('data', (d) => (saveLog += d));
      saveChild.stderr.on('data', (d) => (saveLog += d));
      try {
        let saveReady = false;
        for (let i = 0; i < 50 && !saveReady; i++) {
          try {
            const r = await request({ method: 'GET', path: '/health', sign: false, port: SAVE_PORT });
            saveReady = r.status === 200;
          } catch {
            await new Promise((r) => setTimeout(r, 100));
          }
        }
        check('state-save-failure server starts (unwritable state path)', saveReady, saveLog.slice(-300));
        if (saveReady) {
          const r = await request({
            body: task('gk_24_savefail', baseInput()),
            port: SAVE_PORT,
          });
          const j = parse(r);
          check(
            'state save fails → correct logic-only APPROVE, HTTP 200, signed, no proof',
            r.status === 200 &&
              j?.decision === 'APPROVE' &&
              j?.reason_code === 'VALID_CONDITION' &&
              !('proof' in j) &&
              !('public_signals' in j) &&
              sigValid(r),
            `status=${r.status} body=${String(r.body).slice(0, 200)}`,
          );
        }
      } finally {
        try {
          saveChild.kill('SIGTERM');
        } catch {}
      }
    }
    // 19. PROVING-FAILURE INJECTION (MOST IMPORTANT case) — a second server
    // with a corrupt zkey path must still return the CORRECT logic-only
    // decision, HTTP 200, signed, with no proof. The decision path must
    // survive a totally broken prover.
    {
      const FAIL_PORT = PORT + 1;
      const FAIL_STATE = path.join(TMP, 'state-fail.json');
      const failChild = spawn(process.execPath, [path.join(__dirname, 'server.mjs')], {
        env: {
          ...process.env,
          PORT: String(FAIL_PORT),
          AGENT_GAMES_HMAC_SECRET: SECRET,
          STEAL_HMAC_SECRET: STEAL_SECRET,
          STATE_PATH: FAIL_STATE,
          GK_ZKEY_PATH: path.join(TMP, 'nonexistent', 'gatekeeper_final.zkey'),
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let failLog = '';
      failChild.stdout.on('data', (d) => (failLog += d));
      failChild.stderr.on('data', (d) => (failLog += d));
      try {
        let failReady = false;
        for (let i = 0; i < 50 && !failReady; i++) {
          try {
            const r = await request({ method: 'GET', path: '/health', sign: false, port: FAIL_PORT });
            failReady = r.status === 200;
          } catch {
            await new Promise((r) => setTimeout(r, 100));
          }
        }
        check('failure-injection server starts (bad zkey path)', failReady, failLog.slice(-300));
        if (failReady) {
          const r = await request({
            body: task('gk_24_failinject', baseInput()),
            port: FAIL_PORT,
          });
          const j = parse(r);
          check(
            'proving failure → logic-only APPROVE / VALID_CONDITION, HTTP 200, signed, no proof',
            r.status === 200 &&
              j?.decision === 'APPROVE' &&
              j?.reason_code === 'VALID_CONDITION' &&
              !('proof' in j) &&
              !('public_signals' in j) &&
              sigValid(r),
            `status=${r.status} body=${String(r.body).slice(0, 200)}`,
          );
        }
      } finally {
        try {
          failChild.kill('SIGTERM');
        } catch {}
      }
    }
  } finally {
    cleanup();
  }

  console.log(results.join('\n'));
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => {
  console.error('HARNESS CRASH:', e);
  process.exit(1);
});
