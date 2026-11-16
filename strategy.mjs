// strategy.mjs — "Optimal Strategy" for Steal the VFY (v1).
// Pure, deterministic decision engine. No I/O, no secrets, no proving.
// Source of truth: ../build-spec.txt §06 (Steal the VFY).
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
// Payoff reasoning (relative score = selfBalance - opponentBalance):
//   EXTRACT is the default: it costs 0, gains up to 10, and when both
//   agents EXTRACT simultaneously the exchange is roughly neutral while
//   a one-sided EXTRACT swings the relative score by up to +20.
//   FORTIFY is situational: it costs 2 and only pays when the opponent
//   EXTRACTs this turn (net swing vs. taking the hit is +2*min(E,6)-2,
//   positive when the opponent extracts >= 2). It is worth it when
//   (a) we hold a lead worth protecting late, (b) our own EXTRACT would
//   gain ~0 (opponent fortified + low balance), or (c) the opponent is
//   desperate (behind) and therefore likely to EXTRACT big.
//   HOLD is for when there is nothing to steal (opponent balance ~0)
//   and nothing to protect — paying 2 for FORTIFY would be pure loss.
//
// Rules below are evaluated in order; the first match wins. They are
// deliberately simple and deterministic so the same envelope always
// yields the same action (the circuit proof, when available, is a
// function of the same inputs).

/**
 * Decide a Steal the VFY turn.
 * @param {object} state - envelope.state { selfBalance, opponentBalance,
 *   selfFortifiedUntilTurn, opponentFortifiedUntilTurn }
 *   Balances may be decimal strings or numbers. Fortify fields are a
 *   turn number or null.
 * @param {number} turn - envelope.turn (1..20)
 * @returns {{type:'HOLD'|'FORTIFY'|'EXTRACT', amount?:number}}
 *   EXTRACT carries amount (1..10). HOLD/FORTIFY carry NO amount field
 *   (the platform schema rejects action.amount for HOLD/FORTIFY even
 *   when it is 0 — build-spec §06 "Common mistakes").
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
  const fortTurn = (v) => {
    if (v === null || v === undefined || v === '') return null;
    const n = Number(v);
    // Fortify-until turn must be a non-negative safe integer; a
    // fractional/unsafe value is treated as "not fortified".
    return Number.isSafeInteger(n) && n >= 0 ? n : null;
  };
  const oppFort = fortTurn(s.opponentFortifiedUntilTurn);
  const oppFortifiedNow = oppFort !== null && oppFort >= t;

  // Rule 1 — nothing to steal: opponent is broke. EXTRACT gains 0 and
  // FORTIFY costs 2, so HOLD (free) is strictly best.
  if (opp <= 0) return { type: 'HOLD' };

  // Effective gain if we EXTRACT 10 now (capped by opponent balance,
  // reduced by 6 when the opponent is fortified this turn).
  const extractGain = Math.max(0, Math.min(10, opp) - (oppFortifiedNow ? 6 : 0));

  // Rule 2 — EXTRACT would gain nothing (opponent fortified and low
  // balance). Protect a lead with FORTIFY, otherwise HOLD for free.
  if (extractGain <= 0) {
    return self > opp ? { type: 'FORTIFY' } : { type: 'HOLD' };
  }

  // Rule 3 — late game (turns 18-20): the match is decided by who is
  // ahead at turn 20. Ahead: protect the lead (the opponent, behind,
  // will EXTRACT to catch up, so blunt it). Behind/tied: must EXTRACT.
  if (t >= 18) {
    if (self > opp) return { type: 'FORTIFY' };
    return { type: 'EXTRACT', amount: Math.min(10, Math.max(1, Math.trunc(opp))) };
  }

  // Rule 4 — comfortable lead in mid game: ahead by >= 20 from turn 10
  // on. The opponent is desperate and will EXTRACT; FORTIFY protects
  // the lead for 2 VFY instead of letting them take up to 10.
  if (t >= 10 && self - opp >= 20) return { type: 'FORTIFY' };

  // Rule 5 — default: EXTRACT the maximum. Costs 0, gains up to 10
  // (or up to 4 vs. a fortified opponent), and pressures the opponent.
  // Amount is capped by the opponent's balance so we never ask for
  // more than they hold.
  return { type: 'EXTRACT', amount: Math.min(10, Math.max(1, Math.trunc(opp))) };
}
