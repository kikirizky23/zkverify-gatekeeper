# DEPLOY — steal-v2 (dual agent: Proof Gatekeeper + Steal the VFY)
# Version 1.2.0. Codex review: READY (r2: no MAJOR remaining; 1 MINOR fixed + tested).
# Gatekeeper harness 26/26 PASS. Steal harness 47/47 PASS.
# !!! CIRCUIT SOLVED 16 Nov 2026 — this is a REDEPLOY with working proofs !!!

## What this is
`steal-v2/` is a COPY of `gatekeeper-v2/` (v1.1.0, live) PLUS the Steal
the VFY branch. The Gatekeeper path is preserved exactly; Steal is
additive (new envelope branch, second HMAC secret, second state
namespace, second circuit). Both agents share ONE endpoint URL
(`POST /agent`); the server routes by envelope type and verifies the
HMAC with the CORRECT per-event secret.

## !!! CIRCUIT SOLVED — proofs now generate + verify !!!
The vfy-policy circuit's witness calculation used to fail at exactly
THREE asserts in template VfyPolicyProof_154 (lines 72, 90, 149). The
full component wiring was traced from the WAT disassembly and every
assert decoded (circuit-steal/WIRING-TRACE.md):
  - commitment = Poseidon_73(strategyParams[0..7], salt) (circomlibjs).
  - sp0 in [1,10]; sp1 = fortify threshold; sp2 = extract threshold;
    sp3 in {0,1}; sp4..sp7 = 0.
  - Action: selfBalance < sp1 -> FORTIFY; else opponentBalance > sp2
    and sp3==0 -> EXTRACT (amount sp0); else HOLD.
Verified end-to-end: a proof from the UNPATCHED wasm + zkey verifies
(`groth16.verify = true`) against circuit-steal/vk.json.
Fixed policy ("Optimal Strategy v1"): sp = [10, 30, 0, 0, 0, 0, 0, 0].
Implementation: prove-steal.mjs (Poseidon commitment + fixed params +
decideSteal validation) and strategy.mjs (circuit policy exactly).

## Deploy status (16 Nov 2026)
- v1.2.0 was ALREADY DEPLOYED ~08:45 WIB (GitHub 2 commits, Railway
  STEAL_HMAC_SECRET set, service Online, both platform preflights
  ok:true, Steal agent ACTIVE). That deploy carries the OLD
  prove-steal.mjs (commitment = vk_hash, WRONG) — so live Steal turns
  still return HOLD with NO proof (-2/turn).
- THIS redeploy pushes the SOLVED code (same v1.2.0 version number;
  the fix is in prove-steal.mjs / strategy.mjs / harness-steal.mjs /
  package.json). After redeploy, Steal turns return the strategy action
  (EXTRACT/FORTIFY/HOLD) WITH a verifying policyProof.
- package.json NOW includes circomlibjs ^0.1.7 (Poseidon for the
  commitment) alongside snarkjs ^0.7.6 — Railway `npm install` picks
  it up on redeploy. No new env vars are needed (both HMAC secrets
  are already set).

## Files that change (vs. the live gatekeeper-v2 deploy)
Repo: https://github.com/kikirizky23/zkverify-gatekeeper
(ONE repo, ONE Railway service, ONE endpoint URL — both agents.)

NEW files (add):
- strategy.mjs            "Optimal Strategy" decision engine (pure).
- prove-steal.mjs         Groth16 proving for vfy-policy (best-effort).
- harness-steal.mjs       Steal harness (37 tests).
- circuit-steal/vfy-policy.wasm        (2,991,212 B)
- circuit-steal/vfy-policy_final.zkey  (810,586 B)
- circuit-steal/vk.json                (nPublic 9, groth16/bn128)
- codex-review*.log, codex-assert*.log (review evidence; optional)

CHANGED files:
- server.mjs              Dual-mode (Gatekeeper UNCHANGED + Steal branch,
                          dual HMAC, agent-match checks, validate-before-
                          replay, persist-only-valid). Gatekeeper harness
                          still 26/26. (Comments updated: circuit SOLVED.)
- prove-steal.mjs         SOLVED: commitment = Poseidon(sp, salt) via
                          circomlibjs; fixed STRATEGY_PARAMS [10,30,0,0,
                          0,0,0,0]; decideSteal validation + explicit
                          turn/balance validation (Codex r1 MAJOR + r2
                          MINOR fixed).
- strategy.mjs            REWRITTEN to implement exactly the circuit
                          policy (was a 5-rule heuristic the circuit
                          cannot express). POLICY thresholds match
                          STRATEGY_PARAMS.
- package.json            name zkverify-gatekeeper-steal, version 1.2.0.
                          Dependencies: snarkjs ^0.7.6 AND circomlibjs
                          ^0.1.7 (NEW — Poseidon for the commitment).
                          Scripts unchanged.
- .env.example            Documents STEAL_HMAC_SECRET (second secret).
- harness.mjs             Only change: spawns the server with BOTH dummy
                          secrets (STEAL_HMAC_SECRET added to all 3
                          spawn envs). All 26 Gatekeeper tests unchanged.
- harness-steal.mjs       Steal harness (47 tests — was 37; added proof
                          verification, FORTIFY/HOLD proofs, wrong-action
                          + invalid-input rejection tests).

UNCHANGED (Gatekeeper, do not touch):
- decision.mjs, prove.mjs, circuit/ (gatekeeper.wasm/.zkey/vk.json),
  README.md content for Gatekeeper (see note below).

## Railway env vars (TWO secrets — both required)
The server REFUSES to start if either is missing (fail-safe).
- AGENT_GAMES_HMAC_SECRET  (existing, Gatekeeper kixbt-gatekeeper)
  — already set in Railway. DO NOT change it.
- STEAL_HMAC_SECRET        (NEW — Steal kixbt-steal)
  — the 64-char secret from the kixbt-steal agent registration.
  Read it from ~/workspace/zkverify/hmac-secret-steal.txt (mode 600)
  on the VM. NEVER print it, NEVER paste it into chat, NEVER commit
  it. Set it in Railway as a SECOND env var alongside
  AGENT_GAMES_HMAC_SECRET (same service, same deploy).
  If the secret is ever rotated on the platform, update this var and
  redeploy; the old secret stops working immediately.

## Deploy steps (parent agent / browser task — NOT from a subagent)
1. Push steal-v2/ contents to the repo (root commit), replacing
   server.mjs / prove-steal.mjs / strategy.mjs / package.json /
   package-lock.json / .env.example / harness-steal.mjs / DEPLOY.md
   and adding circuit-steal/WIRING-TRACE.md + the new probe scripts.
   Do NOT push state.json, .env, node_modules, or any *secret* file.
   (.gitignore already excludes state.json and .env; verify before push.)
   NOTE: package-lock.json changed (circomlibjs added) — push it so
   Railway installs the exact locked versions.
2. Railway (project "gallant-tranquility", service
   zkverify-gatekeeper-production-6e0a75ac): NO env var changes needed
   (STEAL_HMAC_SECRET + AGENT_GAMES_HMAC_SECRET already set). Redeploy
   (auto on push). Wait for the deploy to go Online (Node 22.23.4,
   port 8080).

## Post-deploy verification (run from the VM with curl — NOT node fetch,
## which cannot parse the Railway URL)
Endpoint: https://zkverify-gatekeeper-production-6e0a75ac.up.railway.app/agent

1. Health (no auth):
   curl -s https://...up.railway.app/health
   Expect: {"ok":true,"service":"proof-gatekeeper+steal-the-vfy",
   "protocolVersion":"v1","mode":"groth16",
   "steal":"optimal-strategy-v1"} (200).
2. Gatekeeper preflight (HMAC with the GATEKEEPER secret):
   Build a signed preflight envelope {type:"agent-games.preflight.v1"}
   and POST it; expect 200 {"ok":true,"protocolVersion":"v1"} and a
   valid x-agent-games-signature (verify with the Gatekeeper secret).
   Then run the platform preflight for the kixbt-gatekeeper agent
   (Dashboard → My Agents → preflightAgent); expect ok:true.
   Then dispatch 1 practice task; expect a correct decision + proof.
3. Steal preflight (HMAC with the STEAL secret):
   Same preflight envelope, signed with the STEAL secret; expect 200
   {"ok":true,"protocolVersion":"v1"} and a valid signature (verify
   with the Steal secret — NOT the Gatekeeper secret).
   Then run the platform preflight for the kixbt-steal agent; expect
   ok:true. (The agent is already active from the 08:45 WIB deploy.)
4. Steal turn end-to-end (the NEW check): dispatch a Steal turn (or
   wait for the next live turn) and confirm the response carries the
   strategy action (EXTRACT 10 / FORTIFY / HOLD) WITH a policyProof
   whose proof verifies with groth16.verify against the vfy-policy
   vk.json (9 public signals). Before this redeploy, turns returned
   HOLD with NO proof; after it, a valid turn MUST have a proof.
   If a Steal turn still returns HOLD with no proof, the redeploy did
   not pick up the new code — check the Railway deploy logs.
5. Confirm the live Gatekeeper still returns proofs: re-run the 3
   practice tasks from the v1.1.0 verification (VK_SUBSTITUTION →
   logic-only REJECT; EXPIRED/RECIPIENT → REJECT + proof that verifies
   with groth16.verify). If any Gatekeeper proof regresses, ROLL BACK.
6. Confirm no secret is exposed: the /health body and all responses
   contain no secret value; the server logs contain no secret.

## Rollback
Revert the repo to the v1.1.0 commit (fc31e51 = logic-only, or the
v1.1.0 Groth16 commit) and redeploy. That restores the Gatekeeper-only
server. The Steal agent will go "unhealthy" again (its endpoint will
401/400 Steal turns), but the Gatekeeper keeps working. No state
migration is needed (state.json is additive; the old server ignores
the stealMatches namespace).
A PARTIAL rollback (keep Steal, revert only the proof fix) is also
possible: revert prove-steal.mjs + strategy.mjs to the 08:45 WIB
deploy state — Steal turns go back to HOLD with no proof, Gatekeeper
unaffected.
