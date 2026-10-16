import XCTest
@testable import GatewayShield

/// Returns a fixed result.
struct ScriptedUpstream: UpstreamModel {
    let result: UpstreamResult
    func complete(_ payload: PromptPayload) async -> UpstreamResult { result }
}

/// Parks every call while closed, so a test can act while a request is
/// suspended inside the gateway. `open()` releases everything parked and lets
/// later calls straight through, so a mutant that sends an extra request
/// upstream fails the test instead of hanging it.
final class GatedUpstream: UpstreamModel, @unchecked Sendable {
    private let state = Locked<(open: Bool, waiting: [CheckedContinuation<Void, Never>], entered: Int)>((false, [], 0))

    var enteredCount: Int { state.withValue { $0.entered } }

    func complete(_ payload: PromptPayload) async -> UpstreamResult {
        await withCheckedContinuation { c in
            let resumeNow = state.withValue { s -> Bool in
                s.entered += 1
                if s.open { return true }
                s.waiting.append(c)
                return false
            }
            if resumeNow { c.resume() }
        }
        return SimulatedModel.respond(to: payload)
    }

    func open() {
        let parked = state.withValue { s -> [CheckedContinuation<Void, Never>] in
            s.open = true
            defer { s.waiting.removeAll() }
            return s.waiting
        }
        parked.forEach { $0.resume() }
    }

    func close() { state.withValue { $0.open = false } }

    /// Yields until `n` calls have entered (bounded, so it never hangs).
    func waitForEntries(_ n: Int) async {
        for _ in 0..<20_000 where enteredCount < n { await Task.yield() }
    }
}

final class GatewayTests: XCTestCase {
    private let prompt = "how do i debounce search input"   // 6 words -> 8 estimated tokens

    func testServedRequestChargesPromptPlusActualOutput() async {
        let h = Harness()
        let device = await h.enroll("a")
        let r = await h.send(device, "alice", prompt, maxOutput: 256)
        guard case .completed(_, let out, _) = SimulatedModel.respond(to: PromptPayload(prompt: prompt, maxOutputTokens: 256)) else {
            return XCTFail("model contract")
        }
        XCTAssertEqual(r.outcome, .served(outputTokens: out, refused: false))
        XCTAssertEqual(r.remainingTokens, 60_000 - 8 - out)
        let stats = await h.gateway.stats
        XCTAssertEqual(stats.served, 1)
        XCTAssertEqual(stats.tokensServed, out)
    }

    func testUnauthenticatedRejectionsRevealNoBudget() async {
        let h = Harness()
        let device = await h.enroll("a")
        let req = await h.request(device, "alice")
        _ = await h.gateway.handle(req)
        let replay = await h.gateway.handle(req)
        XCTAssertEqual(replay.outcome, .rejected(.challenge(.unknownOrUsed)))
        XCTAssertNil(replay.remainingTokens)
        let stats = await h.gateway.stats
        XCTAssertEqual(stats.rejections["challenge"], 1)

        // A signed-in account whose assertion fails learns nothing either.
        let good = await h.request(device, "alice")
        let bad = GatewayRequest(principal: good.principal, session: good.session, path: good.path, payload: good.payload,
                                 challenge: good.challenge,
                                 assertion: Assertion(keyID: device.keyID, counter: 500, clientDataHash: good.assertion.clientDataHash, signature: [0]))
        let rejected = await h.gateway.handle(bad)
        XCTAssertEqual(rejected.outcome, .rejected(.assertion(.badSignature)))
        XCTAssertNil(rejected.remainingTokens)
    }

    func testPayloadLimitsAreEnforcedAfterAuthentication() async {
        let h = Harness()
        let device = await h.enroll("a")
        let zero = await h.send(device, "alice", maxOutput: 0)
        XCTAssertEqual(zero.outcome, .rejected(.invalidPayload))
        let huge = await h.send(device, "alice", maxOutput: 4_097)
        XCTAssertEqual(huge.outcome, .rejected(.invalidPayload))
        XCTAssertNotNil(huge.remainingTokens)
    }

    func testStepUpDemandsAProofBoundToThisChallengeThenGrantsGrace() async {
        let h = Harness(volumeOnlyConfiguration(points: 50))
        let device = await h.enroll("a")
        for _ in 0..<2 { _ = await h.send(device, "alice") }
        let snap = await h.gateway.snapshot(PrincipalID("alice"))
        XCTAssertEqual(snap.level, .stepUp)

        let bare = await h.send(device, "alice")
        XCTAssertEqual(bare.outcome, .rejected(.stepUpRequired))

        // A proof made for a different challenge does not count.
        var req = await h.request(device, "alice")
        let stale = SimulatedUserVerification.makeProof(principal: PrincipalID("alice"), challenge: [0, 0, 0])
        req = GatewayRequest(principal: req.principal, session: req.session, path: req.path, payload: req.payload, challenge: req.challenge,
                             assertion: req.assertion, userVerification: stale)
        let wrong = await h.gateway.handle(req)
        XCTAssertEqual(wrong.outcome, .rejected(.stepUpRequired))

        let served1 = await h.send(device, "alice", withProof: true)
        XCTAssertTrue(isServed(served1))
        let served2 = await h.send(device, "alice")
        XCTAssertTrue(isServed(served2), "inside the grace period")
        h.clock.advance(by: 300_000)
        let afterGrace = await h.send(device, "alice")
        XCTAssertEqual(afterGrace.outcome, .rejected(.stepUpRequired))
    }

    func testThrottleSpacesRequestsWithExactRetryAfter() async {
        let h = Harness(volumeOnlyConfiguration(points: 65))
        let device = await h.enroll("a")
        for _ in 0..<2 { _ = await h.send(device, "alice") }
        let snap = await h.gateway.snapshot(PrincipalID("alice"))
        XCTAssertEqual(snap.level, .throttle)
        let early = await h.send(device, "alice", withProof: true)
        XCTAssertEqual(early.outcome, .rejected(.throttled(retryAfterMs: 30_000)))
        h.clock.advance(by: 29_999)
        let stillEarly = await h.send(device, "alice", withProof: true)
        XCTAssertEqual(stillEarly.outcome, .rejected(.throttled(retryAfterMs: 1)))
        h.clock.advance(by: 1)
        // Throttle implies step-up: past the interval, a request without a proof is still refused.
        let noProof = await h.send(device, "alice")
        XCTAssertEqual(noProof.outcome, .rejected(.stepUpRequired))
        let served3 = await h.send(device, "alice", withProof: true)
        XCTAssertTrue(isServed(served3))
    }

    /// The throttle stamp is written before the upstream `await`. Two requests
    /// that arrive together from a throttled principal: exactly one is served.
    /// (Stamping after the await would serve both.)
    func testConcurrentRequestsCannotSlipPastTheThrottle() async {
        let gate = GatedUpstream()
        let h = Harness(volumeOnlyConfiguration(points: 65), upstream: gate)
        let device = await h.enroll("a")
        gate.open()
        for _ in 0..<2 { _ = await h.send(device, "alice") }
        gate.close()
        h.clock.advance(by: 60_000)
        let first = await h.request(device, "alice", withProof: true)
        let second = await h.request(device, "alice", withProof: true)
        async let a = h.gateway.handle(first)
        await gate.waitForEntries(3)                 // `first` is now suspended upstream
        async let b = h.gateway.handle(second)
        await gate.waitForEntries(4)                 // only reached if `second` got past the throttle
        gate.open()
        let (ra, rb) = await (a, b)
        XCTAssertTrue(isServed(ra))
        XCTAssertEqual(rb.outcome, .rejected(.throttled(retryAfterMs: 30_000)))
        XCTAssertEqual(gate.enteredCount, 3)
    }

    func testBlockIsStickyUntilAnOperatorClearsIt() async {
        let h = Harness(volumeOnlyConfiguration(points: 90))
        let device = await h.enroll("a")
        for _ in 0..<2 { _ = await h.send(device, "alice") }
        let blocked = await h.send(device, "alice", withProof: true)
        XCTAssertEqual(blocked.outcome, .rejected(.blocked))
        XCTAssertEqual(blocked.level, .block)
        h.clock.advance(by: 30 * 86_400_000)
        let later = await h.send(device, "alice", withProof: true)
        XCTAssertEqual(later.outcome, .rejected(.blocked))
        await h.gateway.unblock(PrincipalID("alice"))
        let served4 = await h.send(device, "alice")
        XCTAssertTrue(isServed(served4))
    }

    func testUpstreamFailureChargesWhatIsKnownOrEverythingWhenUnknown() async {
        let unknown = Harness(upstream: ScriptedUpstream(result: .failed(tokensConsumed: nil)))
        let d1 = await unknown.enroll("a")
        let r1 = await unknown.send(d1, "alice", maxOutput: 256)
        XCTAssertEqual(r1.outcome, .rejected(.upstreamFailed))
        XCTAssertEqual(r1.remainingTokens, 60_000 - 8 - 256, "unknown consumption: the reservation stands")

        let known = Harness(upstream: ScriptedUpstream(result: .failed(tokensConsumed: 10)))
        let d2 = await known.enroll("a")
        let r2 = await known.send(d2, "alice", maxOutput: 256)
        XCTAssertEqual(r2.remainingTokens, 60_000 - 8 - 10)
        let inFlight = await known.gateway.inFlight(PrincipalID("alice"))
        XCTAssertEqual(inFlight, 0)
    }

    /// A reservation that outlives its TTL while the request is suspended is
    /// charged by the sweep. The late settle must neither refund it nor release
    /// the in-flight slot twice.
    func testReservationExpiringDuringTheUpstreamCallIsChargedOnce() async {
        var config = GatewayConfiguration.standard
        config.budget.reservationTTL = 1_000
        let gate = GatedUpstream()
        let h = Harness(config, upstream: gate)
        let device = await h.enroll("a")
        let slow = await h.request(device, "alice", maxOutput: 256)
        async let first = h.gateway.handle(slow)
        await gate.waitForEntries(1)
        h.clock.advance(by: 1_000)
        // A second request runs the sweep, which charges the first in full.
        let second = await h.request(device, "alice", maxOutput: 256)
        async let other = h.gateway.handle(second)
        await gate.waitForEntries(2)
        gate.open()
        let r1 = await first
        _ = await other
        XCTAssertTrue(isServed(r1), "the user still gets the answer that was paid for")
        let inFlight = await h.gateway.inFlight(PrincipalID("alice"))
        XCTAssertEqual(inFlight, 0)
        let outstanding = await h.gateway.outstandingReservations
        XCTAssertEqual(outstanding, 0)
        guard case .completed(_, let out, _) = SimulatedModel.respond(to: second.payload) else { return XCTFail() }
        // First: full 264 charged (refill of 1,000 ms adds 0.69 tokens -> floor 0 at this rate).
        let remaining = await h.gateway.remaining(.principal(PrincipalID("alice")))
        XCTAssertEqual(remaining, 60_000 - 264 - (8 + out))
    }

    /// The overspend guarantee comes from reservation, not from the in-flight
    /// limit: with the limit effectively off and 40 requests interleaving, the
    /// total charged still fits the budget.
    func testConcurrentRequestsCannotOverspend() async {
        var config = GatewayConfiguration.standard
        config.budget.perPrincipal = limit(3_000, 86_400_000)
        config.budget.maxInFlightPerPrincipal = 1_000
        let h = Harness(config, yields: 5)
        let device = await h.enroll("a")
        var requests: [GatewayRequest] = []
        for i in 0..<40 { requests.append(await h.request(device, "alice", "summarise section \(i) now", maxOutput: 256)) }
        let results = await withTaskGroup(of: GatewayResponse.self) { group -> [GatewayResponse] in
            for r in requests { group.addTask { await h.gateway.handle(r) } }
            var all: [GatewayResponse] = []
            for await r in group { all.append(r) }
            return all
        }
        // Every prompt is four words, so the gateway estimates the same prompt cost for each.
        let promptCost = WordTokenEstimator().estimate("summarise section 0 now")
        var charged = 0
        var denied = 0
        for r in results {
            switch r.outcome {
            case .served(let out, _): charged += promptCost + out
            case .rejected(.budget): denied += 1
            default: XCTFail("unexpected \(r.outcome)")
            }
        }
        XCTAssertLessThanOrEqual(charged, 3_000)
        XCTAssertGreaterThan(denied, 0, "the budget was actually contended")
        let stats = await h.gateway.stats
        XCTAssertGreaterThan(stats.peakInFlightPerPrincipal, 1, "requests really overlapped")
    }

    func testFlaggedPrincipalsAreNeverEvictedToMakeRoom() async {
        var config = volumeOnlyConfiguration(points: 90)
        config.detector.maxTrackedPrincipals = 2
        let h = Harness(config)
        let device = await h.enroll("a")
        for name in ["alice", "bob"] { for _ in 0..<2 { _ = await h.send(device, name) } }
        let carol = await h.send(device, "carol")
        XCTAssertEqual(carol.outcome, .rejected(.capacity))
        let alice = await h.gateway.snapshot(PrincipalID("alice"))
        XCTAssertEqual(alice.level, .block)
    }

    func testUnflaggedPrincipalsAreEvictedLeastRecentlySeenFirst() async {
        var config = GatewayConfiguration.standard
        config.detector.maxTrackedPrincipals = 2
        let h = Harness(config)
        let device = await h.enroll("a")
        _ = await h.send(device, "alice")
        h.clock.advance(by: 10)
        _ = await h.send(device, "bob")
        h.clock.advance(by: 10)
        let served5 = await h.send(device, "carol")
        XCTAssertTrue(isServed(served5))
        let alice = await h.gateway.snapshot(PrincipalID("alice"))
        let bob = await h.gateway.snapshot(PrincipalID("bob"))
        XCTAssertEqual(alice.served, 0, "alice was the least recently seen")
        XCTAssertEqual(bob.served, 1)
    }

    func testSignatureCheckIsLoadBearingEndToEnd() async {
        for (verifier, expectServed) in [(InsecureSimulatedSignature() as any AssertionSignatureVerifier, false), (AcceptAnySignature(), true)] {
            let h = Harness(verifier: verifier)
            let device = await h.enroll("a")
            let good = await h.request(device, "alice")
            let forged = GatewayRequest(
                principal: good.principal, session: good.session, path: good.path, payload: good.payload, challenge: good.challenge,
                assertion: Assertion(keyID: device.keyID, counter: 99, clientDataHash: good.assertion.clientDataHash, signature: [1])
            )
            let r = await h.gateway.handle(forged)
            XCTAssertEqual(isServed(r), expectServed)
        }
    }

    /// The device assertion proves which install signed, not which account is
    /// asking. An attacker's genuine phone and genuine session cannot spend or
    /// poison someone else's account.
    func testAnAttackerCannotActAsOrGetAnotherAccountBlocked() async {
        let h = Harness(volumeOnlyConfiguration(points: 90))
        let attacker = await h.enroll("attacker")
        let victimDevice = await h.enroll("victim")
        for _ in 0..<3 {
            let own = await h.request(attacker, "attacker")
            let named = GatewayRequest(
                principal: PrincipalID("victim"), session: own.session, path: own.path, payload: own.payload,
                challenge: own.challenge,
                assertion: await attacker.assert(clientDataHash: RequestBinding.clientDataHash(
                    challenge: own.challenge, principal: PrincipalID("victim"), path: own.path, payload: own.payload))
                    ?? own.assertion
            )
            let r = await h.gateway.handle(named)
            XCTAssertEqual(r.outcome, .rejected(.unauthenticated))
            XCTAssertNil(r.remainingTokens)
        }
        let snap = await h.gateway.snapshot(PrincipalID("victim"))
        XCTAssertEqual(snap.level, .allow)
        XCTAssertEqual(snap.remainingTokens, 60_000)
        let victim = await h.send(victimDevice, "victim")
        XCTAssertTrue(isServed(victim))
    }

    func testOversizedPromptIsRefusedAtTheCap() async {
        let h = Harness()
        let device = await h.enroll("a")
        let big = String(repeating: "x,", count: 16_385)   // 32,770 bytes
        let r = await h.send(device, "alice", big)
        XCTAssertEqual(r.outcome, .rejected(.invalidPayload))
        XCTAssertNil(r.remainingTokens)
        let atCap = await h.send(device, "alice", String(repeating: "x", count: 32_768), maxOutput: 10)
        XCTAssertTrue(isServed(atCap))
    }

    /// A prompt with no spaces is one "word" but thousands of tokens. The byte
    /// bound in the estimate and the vendor's reported count both stop it from
    /// riding under the budget.
    func testInputTokensCannotBeUndercharged() async {
        let dense = String(repeating: "x,", count: 8_000)   // 16,000 bytes, one "word"
        XCTAssertGreaterThanOrEqual(WordTokenEstimator().estimate(dense), 4_000)

        let h = Harness(upstream: ScriptedUpstream(result: .completed(inputTokens: 5_000, outputTokens: 10, refused: false)))
        let device = await h.enroll("a")
        let r = await h.send(device, "alice", "short prompt", maxOutput: 100)
        XCTAssertEqual(r.remainingTokens, 60_000 - 5_000 - 10, "the vendor's larger input count is what gets charged")
    }
}
