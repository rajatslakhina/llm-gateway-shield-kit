import XCTest
@testable import GatewayShield

final class PromptShapeTests: XCTestCase {
    func testSmallEditsAreCloseAndUnrelatedPromptsAreFar() {
        let base = "how do i stop my swiftui list from jumping to the top when the data source refreshes"
        let edited = base + " still failing on ios seventeen"
        let other = "explain in exhaustive detail quantum ledger orchid turbine sonnet glacier tariff"
        let threshold = DetectorPolicy().noveltyDistance
        XCTAssertEqual(PromptShape.distance(PromptShape.simHash(base), PromptShape.simHash(base)), 0)
        XCTAssertLessThanOrEqual(PromptShape.distance(PromptShape.simHash(base), PromptShape.simHash(edited)), threshold)
        XCTAssertGreaterThan(PromptShape.distance(PromptShape.simHash(base), PromptShape.simHash(other)), threshold)
    }

    func testNormalisationIgnoresCasePunctuationAndNumbers() {
        XCTAssertEqual(PromptShape.simHash("Retry order 1234, please!"), PromptShape.simHash("retry ORDER 98 please"))
        XCTAssertEqual(PromptShape.normalizedWords("ios17 build"), ["ios", "#", "build"])
        XCTAssertEqual(PromptShape.simHash(""), 0)
        XCTAssertEqual(PromptShape.simHash("!!! ???"), 0)
        XCTAssertNotEqual(PromptShape.simHash("one"), 0, "fewer words than a shingle still hash")
    }
}

final class ScorerTests: XCTestCase {
    private let scorer = ExtractionScorer(policy: DetectorPolicy())

    private func obs(_ at: Millis, _ prompt: String, out: Int = 300, cap: Int = 1_024, refused: Bool = false) -> Observation {
        Observation(at: at, shape: PromptShape.simHash(prompt), promptTokens: 20, outputTokens: out, maxOutputTokens: cap, refused: refused)
    }

    private func botWindow(count: Int = 20) -> [Observation] {
        var rng = SeededGenerator(seed: 7)
        return (0..<count).map { i in
            obs(i * 20_000, "explain in exhaustive detail " + GatewayLab.randomWords(7, &rng), out: 4_096, cap: 4_096)
        }
    }

    private func humanWindow() -> [Observation] {
        let base = "why does my core data fetch return stale objects after a background context save"
        let gaps = [40_000, 190_000, 65_000, 7_200_000, 30_000, 120_000, 55_000, 9_000_000, 80_000, 25_000, 150_000, 45_000]
        var t = 0
        return gaps.enumerated().map { i, g in
            t += g
            return obs(t, i % 4 == 0 ? base : base + " " + GatewayLab.followUps[i % GatewayLab.followUps.count])
        }
    }

    func testColdStartScoresZero() {
        let w = Array(botWindow().prefix(DetectorPolicy().minSamples - 1))
        XCTAssertEqual(scorer.assess(w).score, 0)
        XCTAssertTrue(scorer.assess(w).contributions.isEmpty)
        XCTAssertEqual(scorer.assess([]).score, 0)
    }

    func testScriptedSweepScoresAboveBlockAndPersonBelowStepUp() {
        let bot = scorer.assess(botWindow())
        let human = scorer.assess(humanWindow())
        XCTAssertGreaterThanOrEqual(bot.score, EnforcementPolicy().blockAt)
        XCTAssertLessThan(human.score, EnforcementPolicy().stepUpAt)
        XCTAssertEqual(bot.score, bot.contributions.values.reduce(0, +), "every point is attributed")
    }

    /// Each feature is load-bearing: removing one ramp lowers the bot's score
    /// by exactly that feature's contribution.
    func testEveryFeatureContributes() {
        let window = botWindow()
        let full = scorer.assess(window)
        for feature in [Feature.novelty, .cadence, .lengthSaturation, .volume] {
            var policy = DetectorPolicy()
            policy.ramps[feature] = nil
            let without = ExtractionScorer(policy: policy).assess(window)
            let points = full.contributions[feature] ?? 0
            XCTAssertGreaterThan(points, 0, "\(feature) contributes to the bot's score")
            XCTAssertEqual(without.score, full.score - points, "\(feature)")
        }
    }

    func testFeatureValuesOnKnownWindows() {
        let f = scorer.features(botWindow())
        XCTAssertEqual(f.noveltyPermille, 1_000)
        XCTAssertEqual(f.cadenceIrregularityPermille, 0, "exactly 20 s apart")
        XCTAssertEqual(f.lengthSaturationPermille, 1_000)
        XCTAssertEqual(f.requestsPerHour, 180)

        let refusals = (0..<10).map { obs($0 * 1_000, "same question", refused: $0 < 3) }
        XCTAssertEqual(scorer.features(refusals).refusalPermille, 300)
        XCTAssertEqual(scorer.features(refusals).noveltyPermille, 0)
    }

    /// Observations arrive in completion order; two overlapping requests can
    /// complete out of arrival order. That must not read as an infinite rate.
    func testOutOfOrderCompletionsDoNotInflateVolume() {
        let window = [obs(3_600_000, "a"), obs(0, "b")]
        XCTAssertEqual(scorer.features(window).requestsPerHour, 1)
    }

    func testDegenerateTimingDoesNotTrap() {
        let burst = (0..<12).map { _ in obs(5, "x") }
        let f = scorer.features(burst)
        XCTAssertEqual(f.requestsPerHour, Int.max, "zero span saturates instead of dividing by zero")
        XCTAssertEqual(f.cadenceIrregularityPermille, 0)
        let backwards = [obs(10_000, "a"), obs(0, "b"), obs(Int.min, "c"), obs(Int.max, "d")]
        _ = scorer.features(backwards)   // must not trap
        let extremes = [Observation(at: 0, shape: 0, promptTokens: Int.max, outputTokens: Int.max, maxOutputTokens: Int.max, refused: false),
                        Observation(at: 1, shape: 1, promptTokens: -1, outputTokens: -1, maxOutputTokens: -1, refused: true)]
        XCTAssertTrue(extremes[0].saturated)
        XCTAssertFalse(extremes[1].saturated)
        _ = scorer.features(extremes)
    }

    func testRampsInBothDirectionsAndDegenerate() {
        let rising = FeatureRamp(weight: 20, zeroAt: 100, fullAt: 200)
        XCTAssertEqual(rising.points(for: 100), 0)
        XCTAssertEqual(rising.points(for: 150), 10)
        XCTAssertEqual(rising.points(for: 200), 20)
        XCTAssertEqual(rising.points(for: Int.max), 20)
        XCTAssertEqual(rising.points(for: Int.min), 0)
        let falling = FeatureRamp(weight: 20, zeroAt: 200, fullAt: 100)
        XCTAssertEqual(falling.points(for: 200), 0)
        XCTAssertEqual(falling.points(for: 150), 10)
        XCTAssertEqual(falling.points(for: Int.min), 20)
        let step = FeatureRamp(weight: 5, zeroAt: 10, fullAt: 10)
        XCTAssertEqual(step.points(for: 9), 0)
        XCTAssertEqual(step.points(for: 10), 5)
        // The span Int.max - Int.min does not fit in Int; it saturates, so the ramp
        // degrades to its endpoints instead of trapping.
        XCTAssertEqual(FeatureRamp(weight: 5, zeroAt: Int.min, fullAt: Int.max).points(for: 0), 5)
        XCTAssertEqual(FeatureRamp(weight: 5, zeroAt: Int.min, fullAt: Int.max).points(for: Int.min), 0)
        XCTAssertEqual(FeatureRamp(weight: -3, zeroAt: 0, fullAt: 1).points(for: 1), 0, "negative weights clamp to 0")
    }

    func testScoreIsClampedTo100() {
        var policy = DetectorPolicy(minSamples: 2)
        policy.ramps = [.volume: FeatureRamp(weight: 500, zeroAt: 0, fullAt: 1)]
        let s = ExtractionScorer(policy: policy).assess([obs(0, "a"), obs(0, "b")])
        XCTAssertEqual(s.score, 100)
    }

    func testPolicyClampsNonsense() {
        let p = DetectorPolicy(windowSize: -3, minSamples: 999, noveltyDistance: 500, maxTrackedPrincipals: 0)
        XCTAssertEqual(p.windowSize, 2)
        XCTAssertEqual(p.minSamples, 2)
        XCTAssertEqual(p.noveltyDistance, 64)
        XCTAssertEqual(p.maxTrackedPrincipals, 1)
    }
}

final class EnforcementTests: XCTestCase {
    private let policy = EnforcementPolicy(stepUpAt: 40, throttleAt: 60, blockAt: 80, hysteresis: 10, minHoldMs: 1_000)

    func testEscalatesImmediatelyAndSkipsLevels() {
        XCTAssertEqual(policy.next(current: .allow, since: 0, score: 85, now: 0), .block)
        XCTAssertEqual(policy.next(current: .allow, since: 0, score: 65, now: 0), .throttle)
        XCTAssertEqual(policy.next(current: .stepUp, since: 0, score: 41, now: 0), .stepUp)
    }

    func testDeEscalatesOneLevelOnlyAfterHoldAndHysteresis() {
        XCTAssertEqual(policy.next(current: .throttle, since: 0, score: 0, now: 999), .throttle, "hold not served")
        XCTAssertEqual(policy.next(current: .throttle, since: 0, score: 55, now: 5_000), .throttle, "inside hysteresis band (60-10)")
        XCTAssertEqual(policy.next(current: .throttle, since: 0, score: 49, now: 5_000), .stepUp)
        XCTAssertEqual(policy.next(current: .throttle, since: 0, score: 0, now: 5_000), .stepUp, "one step at a time")
        XCTAssertEqual(policy.next(current: .stepUp, since: 0, score: 29, now: 5_000), .allow)
    }

    func testBlockIsSticky() {
        XCTAssertEqual(policy.next(current: .block, since: 0, score: 0, now: Int.max), .block)
    }

    func testThresholdsAreForcedIntoOrder() {
        let p = EnforcementPolicy(stepUpAt: 90, throttleAt: 10, blockAt: 5, minHoldMs: -1, throttleIntervalMs: 0)
        XCTAssertLessThanOrEqual(p.stepUpAt, p.throttleAt)
        XCTAssertLessThanOrEqual(p.throttleAt, p.blockAt)
        XCTAssertEqual(p.minHoldMs, 0)
        XCTAssertEqual(p.throttleIntervalMs, 1)
        XCTAssertEqual(p.next(current: .allow, since: Int.min, score: 95, now: Int.max), .block)
    }
}
