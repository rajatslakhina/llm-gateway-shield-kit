# GatewayShield

**If your iOS app has an LLM endpoint, anyone who can copy a request out of Charles Proxy can use it for free.** GatewayShield is an abuse-resistant gateway that sits between an iOS app and a model vendor. Every request has to come from a signed-in account and be signed by an attested app install. Every account, install and the fleet as a whole spend from reserved token budgets. Traffic shaped like a distillation sweep gets an explainable score and escalating responses (step-up, then throttle, then block), and the people who use the app normally aren't punished for it.

Swift 6 with strict concurrency. No dependencies. 81 XCTest tests, green in CI on Linux and macOS (details under [Verification](#verification)).

> Demo app: **[llm-gateway-shield-demo-app](https://github.com/rajatslakhina/llm-gateway-shield-demo-app)**. It's a separate repo that pulls this package as a remote dependency, resolved from the 1.x range starting at 1.0.0. See [Verification](#verification) for exactly what has and hasn't been run.

---

## Why this matters

An LLM feature in an iOS app needs a proxy that holds your vendor key, and a script can call anything the app can call. These are the failure modes, and each one costs real money or real model value:

- **Replay and tampering.** Someone captures one request and replays it, or changes `max_tokens` from 512 to 4,096 on the way through.
- **Acting as someone else.** A request that just names an account. A genuine device signature doesn't prove the account belongs to whoever sent the request.
- **Concurrency overspend.** A budget that checks and then charges lets 50 parallel requests all pass the check before any of them is charged.
- **Cheap tokens.** A 400 KB prompt with no spaces counts as one "word" to a naive estimator.
- **Account farms.** One phone, twenty free accounts, twenty free daily allowances.
- **Distillation.** In October 2026 Anthropic described defending against large-scale extraction of model outputs ([Technology.org, 14 Oct](https://www.technology.org/2026/10/14/anthropic-claude-distillation-attacks-safeguards-90-99-percent/)). That traffic has a recognisable shape: it covers new ground on every call, runs on a timer, and asks for the longest answer it can get.

The usual answer is a per-user rate limit plus an API key shipped in the app. This package is what an Engineering Lead would put in front of the vendor instead, with each decision written down and tested.

## Architecture

```
iOS app                                     Gateway (Swift on the server)                         Vendor
───────                                     ─────────────────────────────                         ──────
GatewayClient ──1. GET challenge────────▶  ChallengeStore    single-use, TTL, bounded
   │
   ├─ session token (signed-in account)     prompt-size cap → SessionAuthenticator: principal == session's
   ├─ DeviceAttester (App Attest key)       KeyRegistry       replay WINDOW, signature, accounts per key
   │   signs hash(challenge, principal,
   │   path, prompt, maxOutputTokens)       EnforcementLevel  allow → step-up → throttle → block
   │                                        BudgetLedger      reserve prompt+maxOut on 3 scopes
   └──2. POST request + assertion ───────▶                    ─── await upstream ──────────────▶  model
                                            settle max(estimate, vendor input) + output, refund rest
                                            ExtractionScorer  novelty · cadence · length saturation
                                                              · refusal probing · volume
```

| Type | Responsibility |
|---|---|
| `ShieldGateway` (actor) | The request pipeline. Checks run cheapest and least trusting first. Steps 1 to 4 never suspend; the upstream call is the only `await`. |
| `SessionAuthenticator` | Confirms the account named in the request belongs to the caller's session. The device assertion alone can't prove that. |
| `ChallengeStore` | Single-use server nonces with a TTL and a hard capacity (the oldest is evicted). The issue-order queue is compacted, so it stays bounded too. |
| `RequestBinding`, `CanonicalWriter` | The assertion covers a length-prefixed, domain-separated hash of the challenge, account, path, prompt and `maxOutputTokens`. |
| `ReplayWindow` | An RFC 4303-style 64-wide anti-replay window over the App Attest counter. |
| `KeyRegistry` | Attested keys, revocation, and a cap on accounts per key. |
| `BudgetLedger` | Reserve-then-settle token buckets per account, per key and for the whole fleet. |
| `PromptShape`, `ExtractionScorer` | 64-bit SimHash prompt shapes (no prompt text is stored) and an explainable score from 0 to 100. |
| `EnforcementPolicy` | Escalates at once. De-escalates one level at a time, with hysteresis and a minimum hold. Block is sticky. |
| `GatewayClient` (actor) | The iOS side: fetch a challenge, attach the session and assertion, retry once for a stale challenge or a first step-up. At most 3 attempts. |
| `GatewayLab` | A deterministic virtual-time simulation of people, scrapers and attackers. The demo renders it and the tests assert on it. |
| `GatewayShieldUI` | The SwiftUI lab screen the demo app shows. |

## Design decisions, trade-offs and rejected alternatives

**1. The account comes from the session, not from the request body.** An App Attest assertion proves which *install* signed a request. It doesn't prove which *account* is asking. If the gateway trusted the named account, an attacker could use their own genuine phone to spend someone else's budget, or send scripted traffic under that account's name until it got blocked. So `SessionAuthenticator` must confirm the account belongs to the caller's session, and this check runs before the assertion is verified. `testAnAttackerCannotActAsOrGetAnotherAccountBlocked` covers this, as does the forgery lab's impersonation check.

**2. A replay window instead of App Attest's "counter must increase" rule.** Apple's guidance is to reject any assertion whose counter isn't greater than the stored one. But the Secure Enclave picks the counter, so two requests a phone sends at once can arrive in the opposite order from the one they were signed in, and the second legitimate request gets rejected. `ReplayWindow` accepts any counter it hasn't seen within 64 of the highest, and still rejects every duplicate.
- *Rejected:* serialising every request on the client, which adds latency to every call to guard against a rare race.
- *Rejected:* a strict counter, which produces false replays under concurrency.
- `testStrictCounterRuleWouldRejectLegitimateReordering` shows both behaviours side by side.

**3. The counter is recorded only after the signature verifies.** Otherwise one unsigned assertion with counter `UInt32.max` would lock the real device out permanently.

**4. `maxOutputTokens` is inside the signed hash.** Raising the cap in transit breaks the binding. Fields are length-prefixed because plain concatenation lets bytes move from one field to another without changing the hash.

**5. Reserve, then settle, and never trust a low token estimate.**
- **Reserve before the call.** The gateway reserves `estimatedPrompt + maxOutputTokens` on all three scopes before calling the vendor. The reservation is all-or-nothing across scopes. Concurrent requests therefore can't spend more than is left, provided the estimate is at least the vendor's real input count. When it's lower (dense CJK text can be), the shortfall is charged at settle time and the bucket goes into bounded debt.
- **Estimate pessimistically.** The estimate is the larger of about 4/3 tokens per word and one token per 4 UTF-8 bytes.
- **Settle on the vendor's count.** At settle time the gateway charges the larger of its estimate and the vendor's reported input count, plus the actual output.
- **Cap the prompt.** Prompts over `maxPromptBytes` (32 KB by default) are refused before anything hashes them.
- *Trade-off:* while a large reservation is outstanding, a request can be denied even though it would fit once that reservation's unused part is refunded.
- *Rejected:* check-then-charge, which overspends under concurrency. `testConcurrentRequestsCannotOverspend` turns the in-flight limit off and the guarantee still holds, so the guarantee comes from the reservation.

**6. Balances are kept in token-milliseconds.** A bucket of `T` tokens per `W` ms refills at exactly `T` units per ms, so refill is exact integer arithmetic. `BudgetLimit` refuses any configuration where `T × W` would overflow.

**7. Fail closed when unsure.**
- A vendor timeout of unknown cost is charged at the full reservation.
- A reservation not settled within its TTL is charged, and its in-flight slot is freed.
- A late settle after that refunds nothing (`testReservationExpiringDuringTheUpstreamCallIsChargedOnce`).
- Overcharges are refunded. Undercharges put the bucket into debt, floored at one window.

**8. The attested key is a budget scope.** Per-account signals miss a farm whose accounts each look human. In the Account farm lab every account stays at `allow`, and 39 calls are denied at the key's scope.

**9. Explainable scoring, not a classifier.** The score is five features, each a weighted linear ramp, summed to 0 to 100. Every point is attributed to a named feature, so support can tell a user why they were asked to verify.

| Feature (weight) | What it measures | Why it matters |
|---|---|---|
| Novelty (30) | Share of prompts more than 14 bits (SimHash) away from every earlier prompt in the window | People iterate on one question; a sweep covers new ground on every call |
| Machine cadence (25) | Mean absolute deviation of the gaps between requests, divided by the mean gap | Scripts run on a timer |
| Length saturation (20) | Share of completions reaching 90% of the requested cap | Harvesting asks for the longest answer and fills it |
| Refusal probing (10) | Refusal rate | Probing for the edges of the policy |
| Volume (15) | Sustained requests per hour | Pressure |

- Observations are sorted by arrival time before any time-based feature is computed, so overlapping requests that complete out of order don't read as an infinite request rate.
- *Rejected:* an output/prompt token ratio. Short questions with long answers are what normal chat looks like.
- *Rejected:* a learned model. It can't be explained to a user who was blocked, and there's no labelled data on day one.
- `testEveryFeatureContributes` removes four of the five ramps in turn and checks that the score drops by exactly that feature's points. Refusal probing isn't in that test because the bot window has no refusals; `testFeatureValuesOnKnownWindows` pins its value instead.

**10. A graduated response.**
- **Step-up** asks for a fresh user verification. In production that's a passkey assertion with the user-verified flag, because App Attest proves the app and install, not that a person is there. It costs a person a glance and costs a farm a human.
- **Throttle** allows one request per interval.
- **Block** is sticky until an operator clears it.
- Escalation is immediate. De-escalation goes one level at a time, after a minimum hold and below the threshold minus hysteresis.
- De-escalation happens only on served requests. There's no time-based decay, so a step-up or throttle level also persists for a client that can never pass verification (a user with no passkey, or a build without a verifier). For that client it works like a block. This is deliberate: a farm can't wait its way out. Support needs `unblock` for the false positives.

**11. Bounded memory, with the remaining gaps stated.** Challenges (including the issue-order queue), outstanding reservations, buckets (only full, idle buckets are pruned), tracked accounts and the 48-entry observation window all have a cap. When account tracking is full, unflagged accounts are evicted first. If every tracked account is flagged, new accounts are refused (`.capacity`) rather than letting a flood of fresh accounts evict the flags. That trade-off is listed under limits below.

**12. No trapping arithmetic.** Every operation on request or policy input goes through `Saturating`. Ceilings come from `Int.max`. There are no force-unwraps.

**13. Actor reentrancy is handled on purpose.** `ShieldGateway.handle` makes every check and state change, including stamping the throttle time, before its single `await`. After the await it reads state again rather than reusing what it read before. `testConcurrentRequestsCannotSlipPastTheThrottle` holds one request inside the vendor call while a second one arrives.

## What the lab shows (default seed)

| Scenario | Result |
|---|---|
| Mixed day (24 virtual hours) | **People:** 8, including a power user (123 calls) and a "curious" user who asks something new every time (peak score 30). All were served on every call, and none reached step-up (40). **Sweep scraper:** blocked at score 85 after 10 served requests (40,960 tokens); 110 of 120 calls refused. **Stealth scraper (human-like timing):** score 51, stuck at step-up with no person to pass it; 80 of 90 calls stopped. |
| Account farm | 5 accounts on one attested install. 2 are refused on every call (limit: 3 accounts per key). The other 3 stay at `allow`; 39 calls are denied at key scope and 0 at account scope. |
| Parallel fan-out | 60 requests from one account in 3 task-group waves against 5,000 tokens. Unsettled reservations never exceed 4, and the total charged stays under 5,000 with no refill. Exact counts vary between runs with task scheduling; the invariants are what the tests assert. |
| Replay & forgery | 15 checks: verbatim replay, captured assertion on a new challenge, raised token cap, forged `UInt32.max` counter (and no lockout afterwards), out-of-order delivery accepted, re-signed duplicate, counter 64+ behind, unattested key, **another account's name from an attacker's phone**, revoked key, expired challenge. |

The thresholds were tuned against this constructed traffic, and real traffic needs its own calibration. The rollout I'd recommend:
1. Run in shadow mode (score and log only) for two weeks.
2. Read the explanations for the top-scoring accounts.
3. Enable step-up before throttle or block.

Shadow mode isn't built into this package.

## Scope and honest limits

- **"Device" means app install.** An App Attest key exists per install, so reinstalling the app mints a new key with a fresh per-key budget and 3 more account slots. The account-per-key limit and the key budget raise the cost of a farm; they don't cap one phone. The production mitigation is App Attest's receipt and fraud-risk metric (Apple's count of keys attested on the device), or DeviceCheck's per-device bits. Neither is implemented here.
- **Capacity limits can become denial of service.** `KeyRegistry` never prunes keys, so once `maxKeys` (1,000,000) is reached, new installs get `.registryFull`. If every tracked account is flagged, new accounts get `.capacity`. Cheap key minting through reinstalls makes both reachable. Production needs key expiry and the fraud-risk signal above.
- **The fleet budget is a shared ceiling.** Farm traffic that stays at `allow` can, with enough cheap installs, drain the 20M-tokens-per-hour global bucket, and then every user gets `.insufficient(.global)`. That's the intended spend cap, but it's also a denial-of-service lever. Alert on global-bucket burn rate.
- **Rate-limit challenge issuance at the edge.** `issueChallenge` is unauthenticated, and a flood evicts other clients' challenges (FIFO). The design assumes a per-IP or per-install rate limit in front of it.
- **Some paths scan linearly.** `pruneFullBuckets` is O(buckets) when the ledger is at its cap, and admitting a new account is O(accounts) when tracking is full. The expiry sweep is O(1) unless a reservation is due.
- **Attestation-object verification is out of scope.** `KeyRegistry.register` records the result of verifying App Attest's attestation (the certificate chain to Apple's root, app id and nonce), but doesn't implement that verification.
- **Signatures, sessions and user verification are simulated** (`InsecureSimulatedSignature`, `SimulatedSessions`, `SimulatedUserVerification`) so the package runs on Linux with no dependencies. In production you'd plug in a CryptoKit `P256.Signing.PublicKey` verifier over App Attest's `authenticatorData || clientDataHash`, your real session-token check, and a passkey verifier.
- **Cold start is free by design.** Below 10 observations the score is 0, so the first 10 requests of any account are never challenged. The per-account and per-key budgets bound what that costs.
- **State lives in one actor's memory.** A multi-instance deployment needs the ledger and replay windows in a shared store, with the same atomicity (a Redis script or one database transaction per reservation).

## How to run it

```bash
git clone https://github.com/rajatslakhina/llm-gateway-shield-kit.git
cd llm-gateway-shield-kit
swift build -Xswiftc -warnings-as-errors
swift test
```

To use it from another package or app:

```swift
.package(url: "https://github.com/rajatslakhina/llm-gateway-shield-kit.git", from: "1.0.0")
// products: "GatewayShield" (core, any platform), "GatewayShieldUI" (SwiftUI lab screen, iOS 17 / macOS 14)
```

```swift
// Every argument after `configuration` is a protocol you implement for your stack.
let gateway = ShieldGateway(
    configuration: .standard,
    clock: yourMonotonicClock,              // GatewayClock
    upstream: yourVendorClient,             // UpstreamModel
    signatureVerifier: yourAppAttestP256,   // AssertionSignatureVerifier
    userVerifier: yourPasskeyVerifier,      // UserVerificationVerifier
    sessions: yourSessionTokenCheck         // SessionAuthenticator
)
let response = await gateway.handle(request)
```

To see it run, use the [demo app](https://github.com/rajatslakhina/llm-gateway-shield-demo-app).

## Verification

- **Local (Linux, Swift 6.0.3):** a clean `swift build -Xswiftc -warnings-as-errors` produces no warnings, and `swift test` passes **81 tests with 0 failures**. `GatewayShieldUI` is SwiftUI, so on Linux it builds as an empty module; only the macOS CI job below compiles it.
- **Mutation checks (run by hand during development, not in CI):** 13 deliberate bugs, and the suite caught every one.
  - stamping the throttle after the `await`
  - skipping the reservation debit
  - ignoring the replay window's seen-bits
  - a reusable challenge
  - skipping the signature check
  - a strict counter in place of the window
  - no refunds
  - no account limit
  - no session check
  - ignoring the vendor's input count
  - no queue compaction
  - an unsorted feature window
  - no prompt cap
- **CI** ([Actions](https://github.com/rajatslakhina/llm-gateway-shield-kit/actions)) is **green on the v1.0.0 commit**, in two jobs:
  - A Linux job in the `swift:6.0` container builds with `-warnings-as-errors` and runs `swift test`.
  - A `macos-15` job runs `swift test`, which also compiles the SwiftUI target, and then `xcodebuild build` of the `GatewayShield-Package` scheme for `generic/platform=iOS Simulator`.
  - The first macOS run caught a real bug that Linux couldn't. A public type named `Observation` shadowed the `Observation` module that `@Observable` expands into. It was renamed to `RequestObservation` before the release.
- **Demo:** the [demo repo](https://github.com/rajatslakhina/llm-gateway-shield-demo-app)'s CI resolves this package from GitHub at 1.0.0 and builds the app for the iOS Simulator. That job is green.
- **Simulator: not run.** The app has never been launched on a Simulator or a device, and there are no screenshots. The demo README explains why.

## License

MIT
