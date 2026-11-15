// decision.mjs — pure, deterministic Proof Gatekeeper decision engine.
// LOGIC-ONLY: no Groth16 proof is generated. A correct decision without a
// valid proof still scores (+12 −2, no reliability bonus) per the game rules.
// Source of truth: ../build-spec.txt (Builder Field Guide, §02/§04).
//
// The 7 trap types (reason codes) and their checks:
//   VALID_CONDITION    — every check passes → APPROVE
//   VK_SUBSTITUTION    — input.proof_vk !== input.registered_vk
//   PROOF_REUSED       — input.proof_tx already seen on a DIFFERENT task_id
//   THRESHOLD_MISMATCH — public_balance < minimum
//   EXPIRED_CONDITION  — current_block > expiry_block
//   RECIPIENT_MISMATCH — recipient !== condition_recipient
//   AMOUNT_OVERFLOW    — amount > max_transfer, amount > public_balance,
//                        or amount <= 0
//
// Check order is fixed and documented (VK → REUSED → THRESHOLD → EXPIRED →
// RECIPIENT → AMOUNT). The platform generates single-trap tasks, so order
// only matters if a task carries two traps at once.

export const REASON_CODES = [
  'VALID_CONDITION',
  'VK_SUBSTITUTION',
  'PROOF_REUSED',
  'THRESHOLD_MISMATCH',
  'EXPIRED_CONDITION',
  'RECIPIENT_MISMATCH',
  'AMOUNT_OVERFLOW',
];

const normAddr = (v) => String(v ?? '').trim().toLowerCase();

// Parse a decimal string/number as BigInt. Returns null on garbage/missing.
function toBig(v) {
  if (v === undefined || v === null || v === '') return null;
  try {
    if (typeof v === 'number') {
      if (!Number.isInteger(v)) return null;
      return BigInt(v);
    }
    const s = String(v).trim();
    if (!/^-?\d+$/.test(s)) return null;
    return BigInt(s);
  } catch {
    return null;
  }
}

/**
 * Decide a gatekeeper task.
 * @param {object} input - envelope.input from the platform
 * @param {(proofTx: string) => string|null} findProofOwner - returns the
 *   task_id that already used this proof_tx, or null. Caller owns the store.
 * @returns {{decision: 'APPROVE'|'REJECT', reason_code: string}}
 */
export function decide(input, findProofOwner) {
  const inp = input && typeof input === 'object' ? input : {};

  // 1. VK_SUBSTITUTION — the proof's VK must equal the registered VK.
  // Missing either side is a fail-closed REJECT (cannot confirm identity).
  const regVk = normAddr(inp.registered_vk);
  const proofVk = normAddr(inp.proof_vk);
  if (!regVk || !proofVk || regVk !== proofVk) {
    return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };
  }

  // 2. PROOF_REUSED — same proof_tx on a different task_id.
  // (Same task_id replays are handled by the server before calling decide.)
  const proofTx = typeof inp.proof_tx === 'string' ? inp.proof_tx.trim() : '';
  if (proofTx && typeof findProofOwner === 'function') {
    const owner = findProofOwner(proofTx);
    if (owner) return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
  }
  // NOTE: a missing/empty proof_tx cannot be checked for reuse. The spec
  // calls proof_tx an "optional on-chain audit pointer", so absence alone
  // is NOT a rejection reason — the other 5 checks still apply.

  // 3. THRESHOLD_MISMATCH — public_balance must be >= minimum.
  const minimum = toBig(inp.minimum);
  const balance = toBig(inp.public_balance);
  if (minimum === null || balance === null || balance < minimum) {
    return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
  }

  // 4. EXPIRED_CONDITION — current_block must be <= expiry_block.
  // Boundary: current == expiry is still valid (expiry block is the last
  // valid block). Only strictly-greater is expired.
  const expiry = toBig(inp.expiry_block);
  const current = toBig(inp.current_block);
  if (expiry === null || current === null || current > expiry) {
    return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
  }

  // 5. RECIPIENT_MISMATCH — recipient must equal condition_recipient.
  const recipient = normAddr(inp.recipient);
  const conditionRecipient = normAddr(inp.condition_recipient);
  if (!recipient || !conditionRecipient || recipient !== conditionRecipient) {
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  }

  // 6. AMOUNT_OVERFLOW — amount must be > 0, <= max_transfer and
  // <= public_balance (a transfer larger than the proven balance cannot
  // execute; fail closed).
  const amount = toBig(inp.amount);
  const maxTransfer = toBig(inp.max_transfer);
  if (
    amount === null ||
    maxTransfer === null ||
    amount <= 0n ||
    amount > maxTransfer ||
    amount > balance
  ) {
    return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };
  }

  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
}

/**
 * Lenient envelope timestamp sanity check (NOT a scoring rule).
 * Returns true if issued_at is present, parseable, not >10 min in the
 * future and not >24h in the past. The platform enforces the 60s response
 * deadline itself; this only guards against grossly stale/replayed
 * envelopes. Preflight is exempt (it must never fail on clock skew).
 */
export function issuedAtSane(issuedAt) {
  if (!issuedAt) return true; // absent timestamp: HMAC already authenticates
  const t = Date.parse(issuedAt);
  if (Number.isNaN(t)) return false;
  const now = Date.now();
  return t <= now + 10 * 60 * 1000 && t >= now - 24 * 60 * 60 * 1000;
}
