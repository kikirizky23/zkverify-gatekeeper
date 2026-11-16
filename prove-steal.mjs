// prove-steal.mjs — Groth16 proving for the vfy-policy circuit (Steal the VFY).
// Pure proving: no HTTP, no decision logic. On ANY failure it throws and
// the caller (server.mjs) falls back to HOLD with no proof (fail-closed).
//
// Circuit inputs (17, recovered by FNV-1a probe + witness-layout check):
//   PUBLIC (8): commitment, matchId, turnNumber, selfBalance,
//     opponentBalance, action, amount, circuitVersion.
//   PRIVATE (9): strategyParams[8], salt.
// Public signals (9, output-then-public order, confirmed via patched
// witness): [wire1, commitment, matchId, turnNumber, selfBalance,
//   opponentBalance, action, amount, circuitVersion].
//   wire1 is a computed internal output (its exact expression is
//   UNRESOLVED — see CIRCUIT-BLOCKER below).
//
// Registered commitment (vk_hash, /api/circuit-info + GET commitment):
//   0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047
//   (commitmentHash == vfyPolicy vkHash; strategy "Optimal Strategy").
//
// ---- CIRCUIT-BLOCKER (status 16 Nov 2026, MUST READ) --------------------
// The witness calculation on the UNPATCHED wasm fails at exactly THREE
// asserts in template VfyPolicyProof_154 (lines 72, 90, 149). All other
// template-154 asserts pass, so the range checks are fine — only these
// three policy/equality asserts fail. Two Codex WAT analyses (logs:
// circuit-steal/codex-assert.log, codex-assert2.log) could NOT identify
// the satisfying inputs: the .sym/.r1cs/circuit source are NOT served
// (404), so the component wiring cannot be mapped to signal names.
// With the CORRECTED function-index mapping (imports 0-3, defined fns
// from 4; call 52=Fr_eq, call 39=Fr_isTrue, call 49=Fr_sub,
// call 58=Fr_mul), the three asserts are EQUALITY checks:
//   line 72:  component[1].signal[1] == commitment
//   line 90:  component[0].signal[0] == matchId
//   line 149: component[7].signal[1] *
//             (component[18].signal[0] - component[7].signal[0])
//             == component[24].signal[0]
// The component identities (which sub-component is 0/1/7/18/24) and
// what strategyParams[8] encodes are UNRESOLVED. strategyParams[4],
// [6], [7] do not appear in the witness at all; strategyParams[5] is
// at witness[1271]. No Poseidon hash of any raw-input combination
// appears anywhere in the 1909-signal witness.
// CONSEQUENCE: generatePolicyProof() currently THROWS for every input
// (witness assert). The server treats that as "no proof" and returns
// HOLD (fail-closed, -2/turn, resolved as HOLD) — the agent stays
// registered and responsive, but it cannot score a verified turn until
// the circuit inputs are resolved. Resolution paths: (a) obtain the
// circuit source / .sym / .r1cs from the zkVerify team, or (b) trace
// the full component wiring in VfyPolicyProof_154_create/_run.
// DO NOT "fix" this by patching the wasm or by submitting a proof
// from the patched wasm — a patched-wasm proof would NOT verify
// against the platform's real VK and would be a false submission.
//
// Strategy-params encoding below (encodeStrategyParams) is a BEST GUESS
// (fortify state in slots 0-1, rest 0), single swappable function.
// A wrong encoding costs the same -2 as an omitted proof (free option);
// a right one gains a verified turn. It is NOT claimed to be correct.

import * as snarkjs from 'snarkjs';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Registered vfy-policy vk_hash (== registered commitmentHash).
export const VFY_VK_HASH =
  '0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047';
export const BN128_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export const STEAL_WASM_PATH =
  process.env.STEAL_WASM_PATH ||
  path.join(__dirname, 'circuit-steal', 'vfy-policy.wasm');
export const STEAL_ZKEY_PATH =
  process.env.STEAL_ZKEY_PATH ||
  path.join(__dirname, 'circuit-steal', 'vfy-policy_final.zkey');
export const STEAL_VK_PATH =
  process.env.STEAL_VK_PATH ||
  path.join(__dirname, 'circuit-steal', 'vk.json');

export function encodeVkHash(hex) {
  return (BigInt(hex) % BN128_PRIME).toString();
}

// matchId: UUID string ("9f4e1b2a-...") -> BigInt (dashes removed), mod p.
// Same encoding as the publicInputsHash formula in build-spec §06.
export function encodeMatchId(matchId) {
  const s = String(matchId ?? '').replace(/-/g, '').trim();
  if (!/^[0-9a-fA-F]+$/.test(s)) throw new Error(`prove-steal: bad matchId ${matchId}`);
  return (BigInt('0x' + s) % BN128_PRIME).toString();
}

export const ACTION_CODE = { HOLD: 0, FORTIFY: 1, EXTRACT: 2 };

// circuitVersion "v1" -> 1 (build-spec §06 publicInputsHash).
export const CIRCUIT_VERSION_FIELD = '1';

/**
 * strategyParams[8] — BEST GUESS (UNVERIFIED, see CIRCUIT-BLOCKER above).
 * Single swappable function. Current guess: the fortify state, which is
 * in the turn envelope but in NONE of the 8 public inputs, so it must
 * reach the circuit through a private input. Slots 0-1 carry it
 * (0 = not fortified); slots 2-7 are 0 (reserved for strategy
 * thresholds). If the circuit is resolved and this encoding is wrong,
 * replace this function only — nothing else changes.
 */
export function encodeStrategyParams(state) {
  const s = state && typeof state === 'object' ? state : {};
  const fort = (v) => {
    if (v === null || v === undefined || v === '') return '0';
    const n = Number(v);
    return Number.isFinite(n) && n >= 0 ? String(Math.trunc(n)) : '0';
  };
  return [
    fort(s.selfFortifiedUntilTurn),
    fort(s.opponentFortifiedUntilTurn),
    '0', '0', '0', '0', '0', '0',
  ];
}

function requireDecimalString(v, name) {
  if (v === undefined || v === null || v === '') {
    throw new Error(`prove-steal: missing input ${name}`);
  }
  const s = String(v).trim();
  if (!/^\d+$/.test(s)) throw new Error(`prove-steal: non-numeric input ${name}: ${s}`);
  return s;
}

/**
 * Generate a Groth16 policy proof for one Steal turn.
 * @param {object} args - { matchId, turn, state, action }
 *   action: { type: 'HOLD'|'FORTIFY'|'EXTRACT', amount?: number }
 *   (amount is 0 for HOLD/FORTIFY; for EXTRACT it is 1..10.)
 * @returns {Promise<{proof, publicSignals}>} — publicSignals has 9
 *   decimal strings in output-then-public order.
 * @throws on ANY failure (bad input, missing circuit file, witness
 *   assert at template lines 72/90/149, prove error). Caller must
 *   fall back to HOLD with no proof. NEVER returns a partial proof.
 */
export async function generatePolicyProof(args) {
  const a = args && typeof args === 'object' ? args : {};
  if (!a.matchId || typeof a.matchId !== 'string') {
    throw new Error('prove-steal: missing matchId');
  }
  const actionType = a.action && a.action.type;
  if (actionType !== 'HOLD' && actionType !== 'FORTIFY' && actionType !== 'EXTRACT') {
    throw new Error(`prove-steal: bad action ${actionType}`);
  }
  const amount =
    actionType === 'EXTRACT'
      ? requireDecimalString(a.action.amount, 'amount')
      : '0';
  if (actionType === 'EXTRACT') {
    const n = BigInt(amount);
    if (n < 1n || n > 10n) throw new Error(`prove-steal: EXTRACT amount out of range: ${amount}`);
  }

  // Fresh random salt per proof. Private input, never in the public
  // signals; fresh salt gives unlinkable commitments.
  const salt = (
    BigInt('0x' + randomBytes(31).toString('hex')) % BN128_PRIME
  ).toString();

  const input = {
    commitment: encodeVkHash(VFY_VK_HASH),
    matchId: encodeMatchId(a.matchId),
    turnNumber: requireDecimalString(a.turn, 'turn'),
    selfBalance: requireDecimalString(a.state?.selfBalance, 'selfBalance'),
    opponentBalance: requireDecimalString(a.state?.opponentBalance, 'opponentBalance'),
    action: String(ACTION_CODE[actionType]),
    amount,
    circuitVersion: CIRCUIT_VERSION_FIELD,
    strategyParams: encodeStrategyParams(a.state),
    salt,
  };

  // Temp witness FILE (groth16.prove needs a file name, not an object).
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'steal-proof-'));
  try {
    const wtnsPath = path.join(dir, 'witness.wtns');
    await snarkjs.wtns.calculate(input, STEAL_WASM_PATH, wtnsPath);
    const { proof, publicSignals } = await snarkjs.groth16.prove(STEAL_ZKEY_PATH, wtnsPath);
    if (!proof || !Array.isArray(publicSignals) || publicSignals.length !== 9) {
      throw new Error('prove-steal: malformed proof output');
    }
    return { proof, publicSignals };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Verify a policy proof locally against the exported vk.json.
 * Used by the harness (and only the harness) to confirm a proof that
 * verifies. Returns true/false, never throws.
 */
export async function verifyPolicyProof(proof, publicSignals) {
  try {
    const vk = JSON.parse(fs.readFileSync(STEAL_VK_PATH, 'utf8'));
    return await snarkjs.groth16.verify(vk, publicSignals, proof);
  } catch {
    return false;
  }
}
