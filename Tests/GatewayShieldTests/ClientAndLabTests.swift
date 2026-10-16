import XCTest
@testable import GatewayShield

/// Replays scripted gateway responses and records what the client sent.
actor ScriptedTransport: GatewayTransport {
    private var script: [GatewayOutcome]
    private(set) var sent: [GatewayRequest] = []
    private var nextChallenge: UInt8 = 0

    init(_ script: [GatewayOutcome]) { self.script = script }

    func challenge() async -> [UInt8] {
        nextChallenge &+= 1
        return [nextChallenge]
    }

    func send(_ request: GatewayRequest) async -> GatewayResponse {
        sent.append(request)
        let outcome = script.isEmpty ? .rejected(.challenge(.expired)) : script.removeFirst()
        return GatewayResponse(outcome: outcome, level: .allow, risk: 0, remainingTokens: nil)
    }
}

final class GatewayClientTests: XCTestCase {
    private func client(_ transport: ScriptedTransport, verifier: Bool = true) -> GatewayClient {
        GatewayClient(principal: PrincipalID("alice"), session: [1], attester: SimulatedDevice(keyID: DeviceKeyID("k"), secret: [1]),
                      transport: transport, userVerifier: verifier ? SimulatedUserVerification() : nil)
    }
    private let payload = PromptPayload(prompt: "hi", maxOutputTokens: 10)

    func testStaleChallengeIsRetriedWithAFreshOne() async {
        let t = ScriptedTransport([.rejected(.challenge(.expired)), .served(outputTokens: 5, refused: false)])
        let result = await client(t).complete(payload)
        XCTAssertEqual(result, .completed(outputTokens: 5, refused: false))
        let sent = await t.sent
        XCTAssertEqual(sent.map(\.challenge), [[1], [2]])
        XCTAssertEqual(sent.map(\.assertion.counter), [1, 2], "the enclave counter advances per assertion")
    }

    func testAttemptsAreCappedEvenIfTheGatewayKeepsSayingRetry() async {
        let t = ScriptedTransport([])
        let c = client(t)
        let result = await c.complete(payload)
        XCTAssertEqual(result, .failed(.challenge(.expired)))
        let attempts = await c.attempts
        XCTAssertEqual(attempts, GatewayClient.maxAttemptsPerCall)
    }

    func testStepUpRetriesOnceWithAProofBoundToTheNewChallenge() async {
        let t = ScriptedTransport([.rejected(.stepUpRequired), .served(outputTokens: 1, refused: false)])
        let result = await client(t).complete(payload)
        XCTAssertEqual(result, .completed(outputTokens: 1, refused: false))
        let sent = await t.sent
        XCTAssertNil(sent.first?.userVerification)
        XCTAssertEqual(sent.last?.userVerification, SimulatedUserVerification.makeProof(principal: PrincipalID("alice"), challenge: [2]))
    }

    func testStepUpWithoutAVerifierOrTwiceGoesBackToTheUI() async {
        let none = ScriptedTransport([.rejected(.stepUpRequired)])
        let r1 = await client(none, verifier: false).complete(payload)
        XCTAssertEqual(r1, .needsUserVerification)
        let twice = ScriptedTransport([.rejected(.stepUpRequired), .rejected(.stepUpRequired)])
        let r2 = await client(twice).complete(payload)
        XCTAssertEqual(r2, .needsUserVerification)
    }

    func testNonRetryableOutcomesAreSurfacedImmediately() async {
        let cases: [(GatewayOutcome, ClientResult)] = [
            (.rejected(.throttled(retryAfterMs: 42)), .retryAfter(42)),
            (.rejected(.budget(.insufficient(.device(DeviceKeyID("k")), retryAfterMs: 7))), .budgetExhausted(scope: .device(DeviceKeyID("k")), retryAfterMs: 7)),
            (.rejected(.budget(.exceedsLimit(.global))), .budgetExhausted(scope: .global, retryAfterMs: nil)),
            (.rejected(.budget(.ledgerFull)), .budgetExhausted(scope: nil, retryAfterMs: nil)),
            (.rejected(.budget(.tooManyInFlight(limit: 4))), .retryAfter(1_000)),
            (.rejected(.blocked), .blocked),
            (.rejected(.assertion(.badSignature)), .failed(.assertion(.badSignature))),
        ]
        for (outcome, expected) in cases {
            let t = ScriptedTransport([outcome])
            let result = await client(t).complete(payload)
            XCTAssertEqual(result, expected)
            let sentCount = await t.sent.count
            XCTAssertEqual(sentCount, 1, "\(outcome) must not be retried")
        }
    }

    func testUnusableAttestationKeyStopsWithoutSending() async {
        let device = SimulatedDevice(keyID: DeviceKeyID("k"), secret: [1], startingCounter: UInt32.max)
        let exhausted = await device.assert(clientDataHash: SHA256.hash([0]))
        XCTAssertNil(exhausted, "the enclave counter cannot pass UInt32.max")
        let t = ScriptedTransport([.served(outputTokens: 1, refused: false)])
        let c = GatewayClient(principal: PrincipalID("alice"), session: [1], attester: device, transport: t, userVerifier: nil)
        let result = await c.complete(payload)
        XCTAssertEqual(result, .attestationUnavailable)
        let sent = await t.sent
        XCTAssertTrue(sent.isEmpty, "nothing is sent without an assertion")
    }
}

final class LabTests: XCTestCase {
    func testMixedDaySeparatesPeopleFromScrapers() async {
        let report = await GatewayLab.run(.mixedDay)
        for f in report.findings { XCTAssertTrue(f.passed, "\(f.title): \(f.detail)") }
        let people = report.personas.filter { $0.kind.isHuman }
        XCTAssertEqual(people.count, 8)
        for p in people {
            XCTAssertEqual(p.served, p.calls, "\(p.id) was refused something")
            XCTAssertLessThan(p.maxRisk, EnforcementPolicy().stepUpAt, "\(p.id)")
        }
        let sweep = report.persona("sweep-scraper")
        XCTAssertEqual(sweep?.finalLevel, .block)
        XCTAssertEqual(sweep?.servedBeforeFirstStop, DetectorPolicy().minSamples, "cold start: exactly minSamples free requests")
        XCTAssertEqual(report.persona("stealth-scraper")?.finalLevel, .stepUp)
    }

    /// The separation must not depend on one lucky seed.
    func testMixedDayHoldsAcrossSeeds() async {
        for seed: UInt64 in [1, 99, 123_456_789] {
            let report = await GatewayLab.run(.mixedDay, configuration: LabConfiguration(seed: seed))
            for f in report.findings { XCTAssertTrue(f.passed, "seed \(seed) — \(f.title): \(f.detail)") }
        }
    }

    /// The lab's verdict is not baked in: with detection switched off the
    /// sweep scraper is never blocked and the finding reports a failure.
    func testMixedDayFindingFailsWhenDetectionIsDisabled() async {
        var config = LabConfiguration()
        config.gateway.detector.ramps = [:]
        let report = await GatewayLab.run(.mixedDay, configuration: config)
        XCTAssertEqual(report.findings.first { $0.title.hasPrefix("Sweep scraper") }?.passed, false)
        XCTAssertEqual(report.findings.first { $0.title.hasPrefix("Stealth scraper") }?.passed, false)
        XCTAssertNotEqual(report.persona("sweep-scraper")?.finalLevel, .block)
    }

    func testAccountFarmIsCappedByDeviceLimits() async {
        let report = await GatewayLab.run(.accountFarm)
        for f in report.findings { XCTAssertTrue(f.passed, "\(f.title): \(f.detail)") }
        XCTAssertEqual(report.stats.rejections["account-limit"], 48)
    }

    func testAccountFarmFindingFailsWithoutTheDeviceBudget() async {
        var config = LabConfiguration()
        config.gateway.budget.perDevice = .clamped(tokens: 10_000_000, windowMs: 86_400_000)
        let report = await GatewayLab.run(.accountFarm, configuration: config)
        XCTAssertEqual(report.findings.first { $0.title.hasPrefix("The device budget") }?.passed, false)
    }

    func testFanOutInvariantsHold() async {
        for _ in 0..<5 {
            let report = await GatewayLab.run(.fanOut)
            for f in report.findings { XCTAssertTrue(f.passed, "\(f.title): \(f.detail)") }
            let p = report.personas.first
            XCTAssertEqual(p?.calls, 60)
            XCTAssertLessThanOrEqual(report.stats.peakInFlightPerPrincipal, 4)
        }
    }

    func testForgeryScenarioRefusesEveryAttack() async {
        let report = await GatewayLab.run(.forgery)
        XCTAssertEqual(report.findings.count, 15)
        for f in report.findings { XCTAssertTrue(f.passed, "\(f.title): \(f.detail)") }
    }
}
