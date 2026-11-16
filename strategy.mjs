// strategy.mjs — "Optimal Strategy" for Steal the VFY (v1).
// Pure, deterministic decision engine. No I/O, no secrets, no proving.
// Source of truth: ../build-spec.txt §06 (Steal the VFY) AND the
// vfy-policy circuit itself (circuit-steal/WIRING-TRACE.md).
//
// Game (per match, 20 turns, highest balance wins, start 100 VFY each):
//   HOLD      — 0 VFY. Safe pass; gains nothing.
//   FORTIFY   — costs 2 VFY. Blocks up to 6 VFY of incoming extraction
//               THIS turn (opponent's EXTRACT gain is reduced by 6).
//   EXTRACT N — 0 VFY cost. Steals up to N VFY (max 10) from the
//               opponent's spendable balance. A fortified opponent
//               reduces the gain by 6. Both agents can EXTRACT
//               simultaneously.
//
// CRITICAL: this engine MUST implement exactly the policy the vfy-policy
// circuit enforces, or no proof can be generated (the circuit recomputes
// the action from the policy thresholds + balances at template line 140
// and the witness fails if the submitted action differs). The circuit's
// policy space is threshold-based only — it cannot express turn-based or
// lead-based rules (turnNumber is not a policy input; the fortify-turn
// fields are not policy inputs). So this engine is the circuit policy:
//
//   Policy thresholds (prove-steal.mjs::STRATEGY_PARAMS, fixed):
//     sp0 = 10  EXTRACT amount.   sp1 = 30  FORTIFY when selfBalance < 30.
//     sp2 = 0   EXTRACT when opponentBalance > 0.   sp3 = 0 (EXTRACT on).
//   Circuit action (L140):
//     selfBalance < 30            -> FORTIFY (amount 0).
//     else opponentBalance > 0    -> EXTRACT 10.
//     else                        -> HOLD (amount 0).
//
// Payoff reasoning (relative score = selfBalance - opponentBalance):
//   EXTRACT is the default: it costs 0, gains up to 10, and when both
//   agents EXTRACT simultaneously the exchange is roughly neutral while
//   a one-sided EXTRACT swings the relative score by up to +20.
//   FORTIFY is for when we are low (< 30): it costs 2 and only pays when
//   the opponent EXTRACTs this turn (net swing vs. taking the hit is
//   +2*min(E,6)-2, positive when the opponent extracts >= 2). At low
//   balance the opponent is most likely to finish us off, so protecting
//   the remainder is worth 2.
//   HOLD is for when there is nothing to steal (opponent balance 0)
//   and nothing to protect — paying 2 for FORTIFY would be pure loss.
//
// Rules below are evaluated in order; the first match wins. They are
// deliberately simple and deterministic so the same envelope always
// yields the same action (the circuit proof is a function of the same
// inputs).

// Policy thresholds — MUST match prove-steal.mjs::STRATEGY_PARAMS.
export const POLICY = { extractAmount: 10, fortifyBelow: 30, extractAbove: 0 };

/**
 * Decide a Steal the VFY turn.
 * @param {object} state - envelope.state { selfBalance, opponentBalance,
 *   selfFortifiedUntilTurn, opponentFortifiedUntilTurn }
 *   Balances may be decimal strings or numbers. Fortify fields are a
 *   turn number or null (accepted but NOT policy inputs — the circuit
 *   does not use them; they are ignored here so the decision matches
 *   the circuit exactly).
 * @param {number} turn - envelope.turn (1..20)
 * @returns {{type:'HOLD'|'FORTIFY'|'EXTRACT', amount?:number}}
 *   EXTRACT carries amount (always POLICY.extractAmount = 10).
 *   HOLD/FORTIFY carry NO amount field (the platform schema rejects
 *   action.amount for HOLD/FORTIFY even when it is 0 — build-spec §06
 *   "Common mistakes").
 */
export function decideSteal(state, turn) {
  const s = state && typeof state === 'object' ? state : {};
  // Validate inputs strictly (Codex review round 1, MINOR): balances
  // must be finite, non-negative, safe integers; turn must be 1..20.
  // Any invalid input → HOLD (deterministic fail-closed). The server
  // already validates before calling, but the engine must be safe for
  // direct callers too.
  const toNum = (v) => {
    if (v === undefined || v === null || v === '') return null;
    const n = Number(v);
    // Require a non-negative SAFE INTEGER directly (Codex review round 2,
    // MINOR): Number.isSafeInteger(Math.trunc(n)) wrongly accepted
    // fractional values like 1.5 by truncating them. isSafeInteger(n)
    // rejects fractions, NaN, Infinity, negatives and unsafe integers.
    if (!Number.isSafeInteger(n) || n < 0) return null;
    return n;
  };
  const self = toNum(s.selfBalance);
  const opp = toNum(s.opponentBalance);
  const t = toNum(turn);
  if (self === null || opp === null || t === null || t < 1 || t > 20) {
    return { type: 'HOLD' };
  }

  // Rule 1 — low balance: FORTIFY. Circuit L140: selfBalance < sp1
  // (30) -> action 1. Protects the remainder when the opponent is most
  // likely to extract big. (Opponent balance is irrelevant here — the
  // circuit fortifies on self-balance alone.)
  if (self < POLICY.fortifyBelow) return { type: 'FORTIFY' };

  // Rule 2 — opponent has something to steal: EXTRACT the max.
  // Circuit L140: opponentBalance > sp2 (0) and not low and sp3==0
  // -> action 2, amount sp0 (10). Costs 0, gains up to 10.
  if (opp > POLICY.extractAbove) {
    return { type: 'EXTRACT', amount: POLICY.extractAmount };
  }

  // Rule 3 — nothing to steal (opponent broke) and nothing to protect:
  // HOLD for free. Circuit L140: action 0.
  return { type: 'HOLD' };
}
