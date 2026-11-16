# vfy-policy circuit — recovery status (16 Nov 2026)
# Agent: kixbt-steal (fc9d5827-a30c-4e1a-a7dc-7b16a1267c6e), event Steal the VFY.
# Commitment registered: 0x6c56509f...be047 (= vfyPolicy vkHash), circuitVersion v1.
# Strategy: "Optimal Strategy".

## Artifacts (verified by sha256 against a fresh download)
- vfy-policy.wasm (2,991,212 B, sha256 bc0998250d2baf75b89deef5306867ffa7085a08d4f7d2caf0dd63a060b134d2)
- vfy-policy_final.zkey (810,586 B, sha256 f9666a1655279ef27f7fee6d535ac8aa9e39286ac40ff6279fea87c21ab6ce41)
- vk.json (Groth16, BN128, nPublic 9, template VfyPolicyProof_154)
- .r1cs and .sym are NOT served (both 404, HTML error page saved as /tmp/vfy.r1cs and /tmp/vfy.sym — NOT real files, do not use).
- Circuit source NOT found via web search. The Skylar participant repo has only a stub proof.js (returns null).

## RECOVERED (proven by experiment)
- Input schema: 10 signals, 17 field elements.
  PUBLIC (8): commitment, matchId, turnNumber, selfBalance, opponentBalance,
    action, amount, circuitVersion.
  PRIVATE (9): strategyParams[8], salt.
  Confirmed via FNV-1a + getInputSignalSize (size 1 = scalar, size 8 = array).
  NOTE: "turnNumber" IS a real input (the earlier note that it was unconfirmed
  was wrong — the first probe script simply did not include it in its list).
- TRUE witness indices (distinctive-value probe, probe_layout.mjs):
  [0]=1, [1]=public output, [2]=commitment, [3]=matchId, [4]=turnNumber,
  [5]=selfBalance, [6]=opponentBalance, [7]=action, [8]=amount,
  [9]=circuitVersion, [10..13]=strategyParams[0..3], [14]=salt,
  strategyParams[5] at [1271].
  strategyParams[4], [6], [7] do NOT appear anywhere in the witness.
- Public signals (9, output-then-public order, via patched witness):
  [wire1, commitment, matchId, turnNumber, selfBalance, opponentBalance,
   action, amount, circuitVersion].
- The wasm/zkey are intact (hashes match a fresh download).

## SOLVED (16 Nov 2026 ~09:05 WIB — full wiring traced, proof verified)
- The UNPATCHED wasm's three failing asserts (template VfyPolicyProof_154,
  lines 72, 90, 149) are now fully decoded and satisfied. Full wiring in
  WIRING-TRACE.md. The corrected function mapping (imports 0-3, defined
  fns from 4) and direct WAT parsing showed the earlier Codex equations
  (codex-assert.log, codex-assert2.log) were WRONG on component indices
  (only 11 sub-components, indices 0-10; 18/24 do not exist) — do not use.
- The three asserts, decoded:
  - L72: commitment == Poseidon_73(sp0..sp7, salt) (circomlibjs Poseidon).
  - L90: GreaterEqThan(sp0, 1) == 1, i.e. sp0 >= 1.
  - L95: LessEqThan(sp0, 10) == 1, i.e. sp0 <= 10 (sp0 in [1,10]).
  - L98: sp3 in {0,1}. L75-78: sp4..sp7 = 0.
  - L140: action = LessThan(selfBalance, sp1)*1 +
    AND(GreaterThan(opponentBalance, sp2), IsZero(sp3),
    NOT(LessThan(selfBalance, sp1)))*2.
    I.e. selfBalance < sp1 -> FORTIFY; else opponentBalance > sp2 and
    sp3==0 -> EXTRACT; else HOLD.
  - L149: action==EXTRACT -> amount == sp0. L153: action!=EXTRACT ->
    amount == 0.
- Strategy params: sp0 = EXTRACT amount [1,10]; sp1 = fortify threshold;
  sp2 = extract threshold; sp3 = extract-enable flag (0/1); sp4..sp7 = 0.
- Verified end-to-end (prove_full.mjs): a witness + Groth16 proof from
  the UNPATCHED wasm + zkey verifies (`groth16.verify = true`) against
  vk.json (9 public signals). Fixed policy ("Optimal Strategy v1"):
  sp = [10, 30, 0, 0, 0, 0, 0, 0]; commitment = Poseidon(sp, salt).
- Implementation: steal-v2/prove-steal.mjs (commitment + fixed params +
  decideSteal validation) and steal-v2/strategy.mjs (circuit policy).
  Harnesses: harness-steal.mjs 47/47 PASS, harness.mjs 26/26 PASS.
  Codex review r2: no MAJOR remaining (1 MINOR fixed + tested).

## Consequence
- generatePolicyProof() (steal-v2/prove-steal.mjs) now returns a verifying
  Groth16 proof for every turn whose action follows the circuit policy.
  The server returns the strategy action + policyProof (no longer
  fail-closed HOLD). Invalid turns still fail closed to HOLD with no
  proof (-2/turn, resolved as HOLD).
- DO NOT "fix" by patching the wasm or submitting a patched-wasm proof:
  it would NOT verify against the platform's real VK. All proofs come
  from the unpatched wasm + zkey only.

## Next step
- Redeploy steal-v2 (GitHub push + Railway auto-deploy; circomlibjs is
  now a dependency in package.json, picked up by `npm install`).
  Parent's job — do NOT deploy from this trace task.

## Key probe scripts (in this dir)
- probe_signals.mjs, probe_broad.mjs (input discovery)
- probe_layout.mjs (true witness indices)
- probe_witness_search.mjs (Poseidon search over full witness)
- probe_line72.mjs, probe_commit.mjs (commitment derivations — WRONG
  constraint, superseded by probe_l72_fix.mjs)
- probe_l72_fix.mjs (L72 solved: commitment = Poseidon(sp, salt))
- probe_full.mjs (WITNESS_OK for the full solved input)
- prove_full.mjs (GROTH16_VERIFY = true — the proof of solution)
- probe_sp0_bound.mjs (sp0 in [1,10]: 10 passes, 11 fails at L95)
- probe_readsig2.mjs, probe_poseidon73c.mjs (signal reading via
  witness-table patch + Scalar.fromArray)
- iter_asserts.mjs (found exactly 3 failing asserts)
- export_vk.mjs (works); export_r1cs.mjs (BROKEN — snarkjs 0.7.6 has no
  zKey.exportR1CS; do not retry that call)
- codex-assert.log (WRONG mapping — do not use its equations)
- codex-assert2.log (CORRECTED mapping but WRONG component indices —
  do not use its equations)
- codex-policy-inputs.log, codex-wat.log (earlier, inconclusive)
- WIRING-TRACE.md (full component map + decoded asserts + solution)
