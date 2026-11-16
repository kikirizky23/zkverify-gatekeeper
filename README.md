# Proof Gatekeeper agent — GROTH16 proof pass (v1.1.0)

Public HTTPS endpoint for zkVerify Agent Games (handle `kixbt`,
competitionUserId `ac0ceb56-99b8-45a7-8809-6f75f322dfea`,
wallet `0x5750068fb2e240015993d4d06e4da7dc3ba0100a`).

**Scope of this pass: GROTH16 proofs.** The endpoint, HMAC auth, preflight,
decision engine (7 trap types) and response signing are complete and
harness-verified, and every provable task now also carries a Groth16 proof
(`proof` + `public_signals`, 13 elements) generated with snarkjs 0.7.6 and
the official `gatekeeper.wasm` / `gatekeeper_final.zkey`. Proving is a
best-effort annotation AFTER the decision is computed and recorded: on any
proving failure/timeout the response is the exact logic-only response
(decision + reason_code), which costs the same −2 as an omitted proof and
never changes the decision. VK_SUBSTITUTION tasks are logic-only by design.
A correct decision with a valid proof scores the full **+12** plus the
reliability bonus — see "Scoring note" below. The taskId encoding is the
plan's §7.4 best guess (see `../groth16-plan.md` §7; single swappable
`encodeTaskId` in `prove.mjs`).

Source of truth: `../build-spec.txt` (Builder Field Guide extracted from
https://agentgames.zkverify.io/build).

## Files

| File | What it is |
|---|---|
| `server.mjs` | HTTP server, Node 22 + snarkjs. `POST /agent`, `GET /` + `/health`. |
| `decision.mjs` | Pure decision engine (importable, no I/O). |
| `prove.mjs` | Groth16 proving (`generateProof`, `encodeTaskId`, `encodeVkHash`). |
| `circuit/` | Official circuit artifacts: `gatekeeper.wasm`, `gatekeeper_final.zkey`, `vk.json`. |
| `harness.mjs` | Local test harness — spawns the server, 23 assertions (incl. proof verify + failure injection). |
| `.env.example` | `AGENT_GAMES_HMAC_SECRET=` + `PORT=3000`. Copy to `.env`. |
| `.gitignore` | `.env`, `state.json`, `node_modules/`. |
| `state.json` | Created at runtime: `{proofOwners, decisions}` (proof-reuse + replay memory). |

## Run

```bash
cp .env.example .env        # fill AGENT_GAMES_HMAC_SECRET from the dashboard (Rotate Secret)
PORT=3000 node server.mjs   # listens on $PORT, default 3000
node harness.mjs            # 19/19 must pass (dummy secret, temp state)
```

Server refuses to start without `AGENT_GAMES_HMAC_SECRET` (exit 1) —
a placeholder secret fails preflight, so failing fast is the correct
behavior (spec §02/§05).

## Protocol implemented (exact, from the spec)

**Inbound — verify HMAC before parsing** (`server.mjs`, spec §02):
`x-agent-games-signature` = HMAC-SHA256 hex of the RAW request body,
keyed by `AGENT_GAMES_HMAC_SECRET`. Constant-time compare; an optional
`sha256=` prefix is tolerated. Mismatch → `401 {ok:false,
error:"bad_signature"}`. Malformed JSON → 400. Unknown `type` → 400.

**Preflight** — request `{"type":"agent-games.preflight.v1",
"agent_id":"agt_...","issued_at":"...","nonce":"abc123"}` →
response `{"ok":true,"protocolVersion":"v1"}`, signed. Preflight answers
unconditionally after HMAC (never fails on clock skew).

**Task** — request:

```json
{"type":"agent-games.proof-gatekeeper.v1","task_id":"gk_8d31_...",
 "mode":"competition","issued_at":"...","deadline_at":"...",
 "input":{"registered_vk":"0x7d...91","proof_vk":"0x13...aa",
  "minimum":"1000","public_balance":"1460","expiry_block":8430000,
  "current_block":8420000,"recipient":"0xDe42...9f01",
  "condition_recipient":"0xDe42...9f01","amount":"500",
  "max_transfer":"1000","proof_tx":"0xa8...2c"}}
```

Response (signed, `x-agent-games-signature` over the raw body):

```json
{"decision":"REJECT","reason_code":"VK_SUBSTITUTION","proof_tx":"0xa8...2c"}
```

`proof` / `public_signals` are **attached** on every provable task
(APPROVE and REJECT). They are omitted only when proving is skipped by
design (VK_SUBSTITUTION) or fails (then the response is the exact
logic-only response). `proof_tx` is echoed when present in the input.

**Decision engine** (`decision.mjs`, fixed check order):
1. `VK_SUBSTITUTION` — `proof_vk !== registered_vk` (case-insensitive; missing either side → REJECT).
2. `PROOF_REUSED` — `proof_tx` already seen on a *different* `task_id` (persisted in `state.json`).
3. `THRESHOLD_MISMATCH` — `public_balance < minimum`.
4. `EXPIRED_CONDITION` — `current_block > expiry_block` (equal is still valid).
5. `RECIPIENT_MISMATCH` — `recipient !== condition_recipient` (case-insensitive).
6. `AMOUNT_OVERFLOW` — `amount <= 0`, `amount > max_transfer`, or `amount > public_balance`.
7. Otherwise `APPROVE` / `VALID_CONDITION`.

All amounts/blocks compare as `BigInt` (decimal strings or JSON numbers).
Same `task_id` replayed returns the stored decision verbatim (idempotent).
Any engine error → REJECT (fail closed, never approve by default).
Response deadline is 60s; the decision path is synchronous (microseconds).

## Scoring note (Groth16 pass)

Per the spec §01 step 05 and the starter prompt: "an omitted or invalid
proof costs −2". Scoring per task: correct decision **+12**, approving a
trap **−6**, rejecting a valid request **−3**, timeout/offline **−2**,
missing/invalid proof **−2**, plus a reliability bonus (verified proofs /
tasks). A correct decision with a valid proof nets the full **+12** plus
the bonus. The prover uses snarkjs 0.7.6 + `gatekeeper.wasm` /
`gatekeeper_final.zkey`, vk_hash
`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`.
If proving fails, the response falls back to logic-only (correct decision
still nets +10) — the fallback is the permanent safety net.

## Spec ambiguities resolved (and how)

1. **HMAC algorithm** — spec says "HMAC" without naming the hash.
   Implemented HMAC-SHA256 hex (the standard for this header style).
   A `sha256=` prefix on the inbound header is tolerated.
2. **APPROVE reason_code** — spec only shows a REJECT example
   (`VK_SUBSTITUTION`). The 7 trap-type names are the reason-code set, so
   APPROVE uses `VALID_CONDITION` (the "no trap" case).
3. **Response shape** — spec example shows exactly
   `{decision, reason_code, proof_tx}`; no `task_id` echo. Implemented
   exactly that (plus `proof`/`public_signals` when the prover pass lands).
4. **`proof_tx` absence** — spec calls it "an optional on-chain audit
   pointer", so a missing/empty `proof_tx` skips the reuse check instead of
   rejecting (the other 5 checks still apply).
5. **Boundary semantics** — `current_block == expiry_block`,
   `amount == max_transfer`, `balance == minimum` all APPROVE
   (expiry/max/minimum are inclusive limits). Harness asserts all three.
6. **Amount vs balance** — `amount > public_balance` is treated as
   `AMOUNT_OVERFLOW` (a transfer larger than the proven balance cannot
   execute; fail closed). The spec's trap list only pairs amount with
   `max_transfer`, so this is an extension — noted here, not hidden.
7. **Deadline/timestamp** — the platform enforces the 60s deadline; the
   agent does NOT reject on `deadline_at` (a skewed clock could turn a
   +12 into a −3). Only a grossly stale/future `issued_at` (>24h old or
   >10 min in the future) is rejected as `EXPIRED_CONDITION`. Preflight
   is exempt from timestamp checks entirely.
8. **Rejected tasks and reuse memory** — a `proof_tx` is recorded as used
   even when its task was REJECTED ("has not already been used for
   another task", spec §04). Same-`task_id` retries replay the stored
   decision instead of tripping `PROOF_REUSED`.

## What remains (not done in this pass)

1. **Hosting** — deploy behind public HTTPS (URL TBD). The platform posts
   to the URL exactly as registered; register the full handler path
   (e.g. `https://<host>/agent`), not just the root.
2. **Dashboard** — register the endpoint, then **Rotate Secret**, copy the
   one-time plaintext into `AGENT_GAMES_HMAC_SECRET`, restart.
3. **Preflight** — must pass on the platform before the agent is marked
   active. Then complete ≥1 unscored practice task.
4. **Round 4** — opens Mon 16 Nov 2026 17:30 WIB, 8 tasks/round, <60s/task.
5. **(Optional, later)** Groth16 prover pass: download
   `gatekeeper.wasm` + `gatekeeper_final.zkey` from `/build`, generate
   proofs with snarkjs, submit via Kurier (vk_hash above), include
   `proof` + `public_signals` in the response.
