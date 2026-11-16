// prove-steal.mjs — Groth16 proving for the vfy-policy circuit (Steal the VFY).
// Pure proving: no HTTP, no decision logic. On ANY failure it throws and
// the caller (server.mjs) falls back to HOLD with no proof (fail-closed).
//
// Circuit inputs (17, recovered + verified by witness/proof experiment):
//   PUBLIC (8): commitment, matchId, turnNumber, selfBalance,
//     opponentBalance, action, amount, circuitVersion.
//   PRIVATE (9): strategyParams[8], salt.
// Public signals (9, output-then-public order, confirmed via a verifying
// proof): [wire1, commitment, matchId, turnNumber, selfBalance,
//   opponentBalance, action, amount, circuitVersion].
//   wire1 = Poseidon_153(matchId, turnNumber, circuitVersion) (public
//   output); commitment = Poseidon_73(strategyParams[0..7], salt).
//
// Registered commitment — FIXED 2026-11-16 (was vk_hash, which was WRONG):
//   0x16b3ed1bc216831d62c8e5c3957d0b7dc6e6c880885092f54357aacc826dc0ef
//   = Poseidon_73(STRATEGY_PARAMS, FIXED_SALT=1), decimal
//   10268784755669786268000742543790426075495395557280715493243260025004759040239.
//   The dashboard originally held the vfyPolicy vk_hash
//   (0x6c56509f…be047) as the commitment. That can never match a proof:
//   the circuit's `commitment` public input is Poseidon(strategyParams,
//   salt), and no salt makes Poseidon equal the vk_hash (254-bit
//   preimage). Every Steal proof (7×, 13:05–13:35 UTC) was rejected with
//   proof_failure −2 for exactly this mismatch. Re-registered on the
//   dashboard 2026-11-16T14:53:26Z; the salt MUST stay 1 and the params
//   MUST stay STRATEGY_PARAMS, or publicSignals[1] diverges from the
//   registered commitment again (harness asserts this).
//
// ---- CIRCUIT — SOLVED 16 Nov 2026 (see circuit-steal/WIRING-TRACE.md) ----
// The witness calculation on the UNPATCHED wasm used to fail at exactly
// THREE asserts in template VfyPolicyProof_154 (lines 72, 90, 149). The
// full component wiring was traced from the WAT disassembly
// (VfyPolicyProof_154_create/_run; 11 sub-components) and every assert
// decoded. Verified end-to-end: a witness + Groth16 proof generated with
// the UNPATCHED wasm + zkey verifies (`groth16.verify = true`) against
// circuit-steal/vk.json (probe: circuit-steal/prove_full.mjs).
//
// Policy (the circuit COMPUTES the action from balances + params):
//   sp0 = EXTRACT amount, must be in [1,10] (L90: sp0>=1, L95: sp0<=10).
//   sp1 = "low balance" threshold: selfBalance < sp1 -> FORTIFY (L140).
//   sp2 = "rich opponent" threshold: opponentBalance > sp2 (and not low
//         and sp3==0) -> EXTRACT (L140).
//   sp3 = extract-enable flag, must be 0 or 1 (L98); 0 = EXTRACT allowed.
//   sp4..sp7 = 0 (L75-78).
//   L149: action==EXTRACT -> amount must equal sp0.
//   L153: action!=EXTRACT -> amount must be 0.
//   L72: commitment == Poseidon_73(sp0..sp7, salt) (circomlibjs Poseidon).
// The decision engine (strategy.mjs::decideSteal) MUST implement exactly
// this policy, or L140 fails and no proof is generated.
// DO NOT "fix" anything by patching the wasm — proofs must come from the
// unpatched wasm + zkey only.

import * as snarkjs from 'snarkjs';
import { buildPoseidon } from 'circomlibjs';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { decideSteal } from './strategy.mjs';

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
 * strategyParams[8] — the FIXED "Optimal Strategy v1" policy, verified
 * against the unpatched circuit (see WIRING-TRACE.md). Single source of
 * truth for the policy thresholds; strategy.mjs::decideSteal MUST
 * implement exactly the same policy, or the circuit's L140 assert
 * (action == computed action) fails and no proof is generated.
 *
 *   sp0 = 10  EXTRACT amount (circuit range [1,10]; 10 = max gain).
 *   sp1 = 30  FORTIFY when selfBalance < 30 (protect when low).
 *   sp2 = 0   EXTRACT when opponentBalance > 0 (any balance worth taking).
 *   sp3 = 0   EXTRACT enabled (1 would block EXTRACT).
 *   sp4..sp7 = 0 (required by the circuit, L75-78).
 *
 * The params are FIXED for the agent (they are the committed policy).
 * They do not depend on the turn state — the circuit computes the action
 * from these thresholds + the balances. The fortify-turn fields in the
 * envelope state are NOT policy inputs to this circuit.
 */
export const STRATEGY_PARAMS = ['10', '30', '0', '0', '0', '0', '0', '0'];

// Fixed salt for the strategy commitment. The salt is a private circuit
// input, but it MUST be fixed (not random): the registered commitment is
// Poseidon_73(STRATEGY_PARAMS, FIXED_SALT), and the platform checks the
// proof's publicSignals[1] against the registered value. A random salt
// per proof (the old code) makes every proof's commitment differ from
// the registered one, so every proof is rejected (7× proof_failure).
export const FIXED_SALT = '1';

// The registered Steal commitment (dashboard, kixbt-steal), as a decimal
// field element and as hex. MUST equal Poseidon_73(STRATEGY_PARAMS,
// FIXED_SALT); MUST match server.mjs::STEAL_COMMITMENT (same hex).
export const REGISTERED_COMMITMENT =
  '10268784755669786268000742543790426075495395557280715493243260025004759040239';
export const REGISTERED_COMMITMENT_HEX =
  '0x16b3ed1bc216831d62c8e5c3957d0b7dc6e6c880885092f54357aacc826dc0ef';

export function encodeStrategyParams(/* state — ignored: policy is fixed */) {
  return [...STRATEGY_PARAMS];
}

// Lazily-built Poseidon (circomlibjs); the circuit's Poseidon_73 is the
// standard circomlibjs Poseidon (verified byte-identical, WIRING-TRACE.md).
let poseidonPromise = null;
function getPoseidon() {
  if (!poseidonPromise) poseidonPromise = buildPoseidon();
  return poseidonPromise;
}

/**
 * commitment = Poseidon_73(strategyParams[0..7], salt), as a decimal
 * string. This is the circuit's `commitment` public input (L72) — NOT
 * the vk_hash. The vk_hash is only the registered circuit identity.
 */
export async function computeCommitment(strategyParams, salt) {
  const poseidon = await getPoseidon();
  const F = poseidon.F;
  const inputs = [...strategyParams, salt].map((x) => BigInt(x));
  return F.toString(poseidon(inputs));
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
 *   The action MUST be the one decideSteal returns for this state —
 *   the circuit recomputes the action from the policy thresholds +
 *   balances (L140) and the proof fails otherwise. This is enforced
 *   below (Codex review, MAJOR): a mismatched action throws a clear
 *   "policy mismatch" error instead of a cryptic circuit assert.
 * @returns {Promise<{proof, publicSignals}>} — publicSignals has 9
 *   decimal strings in output-then-public order.
 * @throws on ANY failure (bad input, policy mismatch, missing circuit
 *   file, witness assert, prove error). Caller must fall back to HOLD
 *   with no proof. NEVER returns a partial proof.
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
  // Defense-in-depth (Codex review, MAJOR): the action must be exactly
  // what decideSteal computes for this state/turn, or the circuit's
  // L140 assert (action == computed action) fails. Reject a mismatch
  // here with a clear error instead of letting the witness throw.
  // Validate turn/balances FIRST (Codex review round 2, MINOR):
  // decideSteal maps invalid inputs to a fallback HOLD, which would
  // pass the comparison below and reach the witness only to fail at
  // L140 (e.g. turn 0 + HOLD: the circuit computes FORTIFY for
  // selfBalance 0 < 30). Reject invalid inputs explicitly instead.
  const validNum = (v, name) => {
    if (v === undefined || v === null || v === '') {
      throw new Error(`prove-steal: missing input ${name}`);
    }
    const n = Number(v);
    if (!Number.isSafeInteger(n) || n < 0) {
      throw new Error(`prove-steal: invalid input ${name}: ${String(v)}`);
    }
    return n;
  };
  const turnNum = validNum(a.turn, 'turn');
  if (turnNum < 1 || turnNum > 20) {
    throw new Error(`prove-steal: turn out of range: ${turnNum}`);
  }
  validNum(a.state?.selfBalance, 'selfBalance');
  validNum(a.state?.opponentBalance, 'opponentBalance');
  const expected = decideSteal(a.state, a.turn);
  const actionMatches =
    expected.type === actionType &&
    (actionType !== 'EXTRACT' || String(expected.amount) === String(a.action.amount));
  if (!actionMatches) {
    throw new Error(
      `prove-steal: policy mismatch — decideSteal says ${expected.type}${expected.amount !== undefined ? ` ${expected.amount}` : ''}, got ${actionType}${a.action.amount !== undefined ? ` ${a.action.amount}` : ''}`,
    );
  }
  const amount =
    actionType === 'EXTRACT'
      ? requireDecimalString(a.action.amount, 'amount')
      : '0';
  if (actionType === 'EXTRACT') {
    const n = BigInt(amount);
    if (n < 1n || n > 10n) throw new Error(`prove-steal: EXTRACT amount out of range: ${amount}`);
  }

  // FIXED salt (see FIXED_SALT): the proof's commitment must equal the
  // registered Poseidon commitment, so the salt cannot be random.
  const salt = FIXED_SALT;

  // Fixed policy params + Poseidon commitment (circuit L72).
  const strategyParams = encodeStrategyParams(a.state);
  const commitment = await computeCommitment(strategyParams, salt);

  const input = {
    commitment,
    matchId: encodeMatchId(a.matchId),
    turnNumber: requireDecimalString(a.turn, 'turn'),
    selfBalance: requireDecimalString(a.state?.selfBalance, 'selfBalance'),
    opponentBalance: requireDecimalString(a.state?.opponentBalance, 'opponentBalance'),
    action: String(ACTION_CODE[actionType]),
    amount,
    circuitVersion: CIRCUIT_VERSION_FIELD,
    strategyParams,
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
