// prove.mjs — Groth16 proving for the gatekeeper circuit (Groth16 pass).
// Pure proving: no HTTP, no decision logic. On ANY failure it throws and
// the caller (server.mjs) falls back to the logic-only response.
//
// Verified method (see ../groth16-plan.md §2.1): witness must be written to
// a FILE first — snarkjs.groth16.prove needs a file name, NOT an in-memory
// witness object (passing the object throws TypeError). Measured on this VM:
// wtns.calculate ~61 ms, groth16.prove ~859 ms, verify ~101 ms.
//
// Circuit inputs (13, plan §2.2) and public-signal order (13, plan §2.3)
// are confirmed by experiment. The taskId encoding is the ONE unresolved
// item (plan §7): encodeTaskId() below implements the §7.4 best guess as a
// single swappable function. A wrong encoding costs the same −2 as an
// omitted proof (free option); a right one gains +2/task + bonus.

import * as snarkjs from 'snarkjs';
import { randomBytes, createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Registered vk_hash (zkVerify mainnet + /api/circuit-info, plan §2.4).
export const VK_HASH =
  '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
export const BN128_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Circuit files. Overridable via env for the harness failure-injection case
// (plan §5 Step 4: corrupt the zkey path → proving must fail closed).
export const WASM_PATH =
  process.env.GK_WASM_PATH ||
  path.join(__dirname, 'circuit', 'gatekeeper.wasm');
export const ZKEY_PATH =
  process.env.GK_ZKEY_PATH ||
  path.join(__dirname, 'circuit', 'gatekeeper_final.zkey');

export function encodeVkHash(hex) {
  return (BigInt(hex) % BN128_PRIME).toString();
}

export function encodeAddress(addr) {
  return BigInt(addr).toString();
}

/**
 * taskId → field element. Plan §7.4 best guess (single swappable function):
 * (a) `gk_<decimal>_<suffix>` or bare `gk_<decimal>` (all-decimal middle
 *     segment) → that integer; (b) otherwise SHA-256 of the full task_id
 *     string as a big integer mod p — the plan's §7.4(c) fallback.
 *     Poseidon-of-bytes (§7.4(b)) is NOT used: circomlibjs buildPoseidon
 *     appeared to hang on this VM and the plan explicitly says "do not
 *     use it". A wrong encoding costs the same −2 as an omitted proof,
 *     so this is a free option, not a blocker.
 * Returns { field, encoding } where encoding is 'decimal' | 'sha256'.
 */
export function encodeTaskId(taskIdString) {
  const s = String(taskIdString ?? '');
  const m = /^gk_(\d+)(?:_|$)/.exec(s);
  if (m) {
    return { field: (BigInt(m[1]) % BN128_PRIME).toString(), encoding: 'decimal' };
  }
  const hash = createHash('sha256').update(s, 'utf8').digest();
  return {
    field: (BigInt('0x' + hash.toString('hex')) % BN128_PRIME).toString(),
    encoding: 'sha256',
  };
}

function requireDecimalString(v, name) {
  if (v === undefined || v === null || v === '') {
    throw new Error(`prove: missing input ${name}`);
  }
  const s = String(v).trim();
  // Non-negative decimal only (Codex review round 1, MINOR): a negative
  // value would be interpreted modulo the field by snarkjs instead of
  // being rejected as malformed.
  if (!/^\d+$/.test(s)) throw new Error(`prove: non-numeric input ${name}: ${s}`);
  return s;
}

function requireHex(v, name) {
  if (v === undefined || v === null || v === '') {
    throw new Error(`prove: missing input ${name}`);
  }
  const s = String(v).trim();
  if (!/^0x[0-9a-fA-F]+$/.test(s)) throw new Error(`prove: non-hex input ${name}: ${s}`);
  return s;
}

/**
 * Generate a Groth16 proof for one task.
 * @param {object} args - { taskId, minimum, publicBalance, expiryBlock,
 *   currentBlock, recipient, conditionRecipient, amount, maxTransfer,
 *   proofVkHash, decision } — decision is 'APPROVE' | 'REJECT'.
 * @returns {Promise<{proof, publicSignals, taskIdField, taskIdEncoding}>}
 * @throws on ANY failure (bad input, missing circuit file, witness assert
 *   e.g. decision != computed verdict at line 102, prove error). Caller
 *   must fall back to logic-only.
 */
export async function generateProof(args) {
  const a = args && typeof args === 'object' ? args : {};
  if (!a.taskId || typeof a.taskId !== 'string') {
    throw new Error('prove: missing taskId');
  }
  if (a.decision !== 'APPROVE' && a.decision !== 'REJECT') {
    throw new Error(`prove: bad decision ${a.decision}`);
  }
  const { field: taskIdField, encoding: taskIdEncoding } = encodeTaskId(a.taskId);

  // Fresh random salt per proof (plan §8). Private input, never in the
  // public signals; fresh salt gives unlinkable commitments.
  const salt = (
    BigInt('0x' + randomBytes(31).toString('hex')) % BN128_PRIME
  ).toString();

  const input = {
    taskId: taskIdField,
    minimum: requireDecimalString(a.minimum, 'minimum'),
    publicBalance: requireDecimalString(a.publicBalance, 'publicBalance'),
    expiryBlock: requireDecimalString(a.expiryBlock, 'expiryBlock'),
    currentBlock: requireDecimalString(a.currentBlock, 'currentBlock'),
    recipient: encodeAddress(requireHex(a.recipient, 'recipient')),
    conditionRecipient: encodeAddress(requireHex(a.conditionRecipient, 'conditionRecipient')),
    amount: requireDecimalString(a.amount, 'amount'),
    maxTransfer: requireDecimalString(a.maxTransfer, 'maxTransfer'),
    registeredVkHash: encodeVkHash(VK_HASH),
    proofVkHash: encodeVkHash(requireHex(a.proofVkHash, 'proofVkHash')),
    salt,
    decision: a.decision === 'APPROVE' ? '1' : '0',
  };

  // Temp witness FILE (groth16.prove needs a file name, not an object).
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gk-proof-'));
  try {
    const wtnsPath = path.join(dir, 'witness.wtns');
    await snarkjs.wtns.calculate(input, WASM_PATH, wtnsPath);
    const { proof, publicSignals } = await snarkjs.groth16.prove(ZKEY_PATH, wtnsPath);
    if (!proof || !Array.isArray(publicSignals) || publicSignals.length !== 13) {
      throw new Error('prove: malformed proof output');
    }
    return { proof, publicSignals, taskIdField, taskIdEncoding };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
