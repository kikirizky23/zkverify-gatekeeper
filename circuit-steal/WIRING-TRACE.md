# vfy-policy circuit — wiring trace (SOLVED 16 Nov 2026 ~09:05 WIB)

Status: **SOLVED.** A valid Groth16 proof was generated with the UNPATCHED
wasm + zkey and verified (`groth16.verify = true`) against
`circuit-steal/vk.json`. All three previously-failing asserts are now
understood and satisfied. See "Verified solution" below.

## Circuit facts

- Template `VfyPolicyProof_154`. Artifacts: `vfy-policy.wasm`
  (2,991,212 B, sha256 `bc099825…134d2`), `vfy-policy_final.zkey`
  (810,586 B, sha256 `f9666a16…ce41`), `vk.json` (Groth16/BN128, nPublic 9).
- Input schema (10 signals, 17 field elements). PUBLIC (8): commitment,
  matchId, turnNumber, selfBalance, opponentBalance, action, amount,
  circuitVersion. PRIVATE (9): strategyParams[8], salt.
- Witness 1909 signals. Public signals (9, output-then-public):
  `[wire1, commitment, matchId, turnNumber, selfBalance, opponentBalance,
  action, amount, circuitVersion]`.
- Main-template local `sig[N]` = global signal offset `N+1`
  (signal storage base 13840, 40-byte stride; `_create` offset 13880).
  - sig[0] = public output (wire1) = Poseidon_153 output.
  - sig[1]=commitment, sig[2]=matchId, sig[3]=turnNumber,
    sig[4]=selfBalance, sig[5]=opponentBalance, sig[6]=action,
    sig[7]=amount, sig[8]=circuitVersion.
  - sig[9..16]=strategyParams[0..7], sig[17]=salt.
  - sig[18]=copy of sp0, sig[19]=copy of sp1, sig[20]=copy of sp2,
    sig[21]=copy of sp3, sig[22]=LessThan output,
    sig[23]=computed action, sig[24], sig[25]=computed products.

## Component map (11 sub-components, creation order)

| idx | template | inputs (sig[1..n] <- source) |
| 0 | Poseidon_73 | sig[1..9] <- main sig[9..17] = [sp0..sp7, salt] |
| 1 | GreaterEqThan_76 | sig[1] <- sig[18] (sp0), sig[2] <- const[193752] (=1) |
| 2 | LessEqThan_77 | sig[1] <- sig[18] (sp0), sig[2] <- const[193712] (=10) |
| 3 | LessThan_79 | sig[1] <- sig[4] (selfBalance), sig[2] <- sig[19] (sp1) |
| 4 | GreaterThan_80 | sig[1] <- sig[5] (opponentBalance), sig[2] <- sig[20] (sp2) |
| 5 | IsZero_81 | sig[1] <- sig[21] (sp3) |
| 6 | AND_82 | sig[1] <- comp[4].sig[0], sig[2] <- comp[5].sig[0] |
| 7 | NOT_83 | sig[1] <- sig[22] (comp[3].sig[0]) |
| 8 | AND_82 | sig[1] <- comp[6].sig[0], sig[2] <- comp[7].sig[0] |
| 9 | IsEqual_84 | sig[1] <- sig[6] (action), sig[2] <- const[244432] (=2) |
| 10 | Poseidon_153 | sig[1] <- sig[2] (matchId), sig[2] <- sig[3] (turnNumber), sig[3] <- sig[8] (circuitVersion) |

Within a sub-component: sig[0]=output, sig[1..n]=inputs.

## Constants (decoded by passing-assert inference + boundary probes)

- const[193672] = **0** (L75–78 pass with sp4..sp7 = 0).
- const[193752] = **1** (action encoding: FORTIFY; also the "true" value
  comparison outputs are asserted against; L98 sp3 ∈ {0,1}).
- const[193712] = **10** (upper bound for sp0; sp0=10 passes, sp0=11
  fails at L95).
- const[244432] = **2** (action encoding: EXTRACT).
- const[246072] = (unused local temp, not needed).

## The three asserts, decoded

- **L72**: `sig[1] == comp[0].sig[0]`, i.e.
  **commitment == Poseidon_73(sp0..sp7, salt)**.
  Poseidon_73 IS the standard circomlibjs Poseidon
  (`buildPoseidon`, 9 inputs). Verified byte-identical:
  Poseidon([0×8, 987654321]) =
  `21779229478436921289257723526110956546041020048321693034520488611431713819059`.
- **L90**: `comp[1].sig[0] == 1`, i.e. **GreaterEqThan(sp0, 1) == 1**,
  i.e. **sp0 >= 1**.
- **L95**: `comp[2].sig[0] == 1`, i.e. **LessEqThan(sp0, 10) == 1**,
  i.e. **sp0 <= 10**. (Together: sp0 ∈ [1,10] — the EXTRACT max.)
- **L98**: `sp3 * (sp3 - 1) == 0`, i.e. **sp3 ∈ {0, 1}**.
- **L140**: `action == sig[22]*1 + comp[8].sig[0]*2`, where
  sig[22] = LessThan(selfBalance, sp1) and
  comp[8] = AND( AND( GreaterThan(opponentBalance, sp2),
  IsZero(sp3) ), NOT(sig[22]) ). I.e. the circuit COMPUTES the action:
  - selfBalance < sp1 → action = 1 (FORTIFY).
  - else opponentBalance > sp2 AND sp3 == 0 → action = 2 (EXTRACT).
  - else → action = 0 (HOLD).
- **L149**: `(amount - sp0) * IsEqual(action, 2) == 0` — if action is
  EXTRACT, amount must equal sp0.
- **L153**: `(1 - IsEqual(action, 2)) * amount == 0` — if action is not
  EXTRACT, amount must be 0.

## Strategy-parameter semantics (the policy)

- **sp0** = EXTRACT amount, ∈ [1,10]. When the action is EXTRACT,
  amount = sp0.
- **sp1** = "low balance" threshold. selfBalance < sp1 → FORTIFY.
- **sp2** = "rich opponent" threshold. opponentBalance > sp2 (and not
  low, sp3==0) → EXTRACT.
- **sp3** = extract-enable flag: 0 = EXTRACT allowed, 1 = EXTRACT blocked.
- **sp4..sp7** = 0 (required by L75–78).
- **salt** = fresh random per proof (private). **commitment =
  Poseidon([sp0..sp7, salt])** (public signal [1]).

The circuit is a POLICY circuit: the params are the policy, the circuit
enforces that the submitted action follows the policy for the given
balances. The decision engine (`strategy.mjs`) MUST implement exactly
this policy, or L140 fails.

## Verified solution (UNPATCHED wasm + zkey, groth16.verify = true)

Input:
- sp = [5, 50, 50, 0, 0, 0, 0, 0], salt = 987654321.
- commitment = Poseidon([5,50,50,0,0,0,0,0,987654321])
  = `1114599281727611740605496417911061267280739422895119970891807066698127003277`.
- matchId=222, turnNumber=3, selfBalance=100, opponentBalance=100,
  action=2 (EXTRACT), amount=5, circuitVersion=1.

Result (`prove_full.mjs`): `WITNESS_OK`, `GROTH16_VERIFY = true`.
publicSignals =
`["20641251449071176087248160895841535844365358787996885798483119875125371750721",
"1114599281727611740605496417911061267280739422895119970891807066698127003277",
"222","3","100","100","2","5","1"]`.
public[0] (wire1) = Poseidon_153(matchId, turnNumber, circuitVersion).

Boundary: sp0=10 passes, sp0=11 fails at L95 → const[193712]=10.

## Hypotheses log

- H1 (WRONG, from codex-assert.log): offset-33 function mapping;
  equations invalid — discarded, do not reuse.
- H2 (WRONG, from codex-assert2.log): L72 = comp[1].sig[1]==commitment
  etc. — component indices 18/24 do not exist (only 11 components).
  Probe scripts built on it tested commitment = (−1 − Poseidon) — failed.
- H3 (CORRECT): direct WAT parse with verified function map
  (4 imports, defined fns from 4; Fr_copy=37, Fr_isTrue=39,
  Fr_toLongNormal=43, Fr_add=48, Fr_sub=49, Fr_eq=52, Fr_mul=58,
  Poseidon_73_create=258, VfyPolicyProof_154_create=420/_run=421).
  Signal-offset arithmetic (base 13840, stride 40) + distinctive-value
  memory probe confirmed the layout. L72 solved by testing
  commitment = Poseidon(sp, salt) — passed, witness then failed at L90.
- H4 (CORRECT): L90/L95 = sp0 range [1,10]; L98 = sp3 ∈ {0,1};
  L140 = action computed from thresholds; L149/L153 = amount rules.
  Full input (sp=[5,50,50,0×5], salt=987654321, EXTRACT 5 @ 100/100)
  → WITNESS_OK → GROTH16_VERIFY = true.

## Implementation (steal-v2/)

- `prove-steal.mjs::encodeStrategyParams` — FIXED policy params
  (was: fortify turns in slots 0–1, WRONG). Now returns the fixed
  "Optimal Strategy v1" thresholds; commitment is computed as
  Poseidon(strategyParams, salt) via circomlibjs (was: vk_hash, WRONG).
- `strategy.mjs::decideSteal` — rewritten to implement exactly the
  circuit policy (was: 5-rule heuristic that the circuit cannot express;
  its actions would fail L140).
- Fixed policy ("Optimal Strategy v1"): sp0=10, sp1=30, sp2=0, sp3=0,
  sp4..sp7=0. I.e. FORTIFY when selfBalance < 30; else EXTRACT 10 when
  opponentBalance > 0; else HOLD.
- `circomlibjs` added to steal-v2 `package.json` (Poseidon for the
  commitment). Railway `npm install` picks it up on redeploy.

## Files

- Probes: `circuit-steal/probe_full.mjs` (WITNESS_OK),
  `circuit-steal/prove_full.mjs` (GROTH16_VERIFY=true),
  `circuit-steal/probe_sp0_bound.mjs` (sp0 ∈ [1,10]),
  `circuit-steal/probe_l72_fix.mjs` (L72 fix),
  `circuit-steal/probe_readsig2.mjs`, `probe_poseidon73c.mjs`
  (signal reading via witness-table patch + Scalar.fromArray).
- Parsers: `/tmp/parse_run.py`, `/tmp/funcmap.py`, `/tmp/funcmap.txt`
  (may be wiped by a VM restart — the conclusions above are the durable
  record).
- WAT: `/tmp/vfy-policy.wat` (20 MB), `/tmp/vfy-run.wat` (2165 lines).
