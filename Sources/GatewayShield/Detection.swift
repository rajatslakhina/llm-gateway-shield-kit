// MARK: - Prompt shape

/// A 64-bit SimHash of a prompt's word 3-shingles.
///
/// Two prompts that differ by a few words land a few bits apart; two unrelated
/// prompts land about 32 bits apart. The gateway only ever stores this shape,
/// never the prompt, so the detector's memory holds no user text.
public enum PromptShape {
    public static func simHash(_ prompt: String) -> UInt64 {
        let words = normalizedWords(prompt)
        guard !words.isEmpty else { return 0 }
        var tallies = [Int](repeating: 0, count: 64)
        let n = 3
        let shingleCount = max(1, words.count - n + 1)
        for start in 0..<shingleCount {
            let end = min(words.count, start + n)
            // start < shingleCount <= words.count and end <= words.count.
            let shingle = words[start..<end].joined(separator: " ")
            let h = fnv1a64(Array(shingle.utf8))
            for bit in 0..<64 {
                tallies[bit] += (h >> UInt64(bit)) & 1 == 1 ? 1 : -1
            }
        }
        var result: UInt64 = 0
        for bit in 0..<64 where tallies[bit] > 0 {
            result |= UInt64(1) << UInt64(bit)
        }
        return result
    }

    public static func distance(_ a: UInt64, _ b: UInt64) -> Int { (a ^ b).nonzeroBitCount }

    /// Lowercased alphanumeric words; digit runs collapse to `#` so a person
    /// retrying with a different number does not look like a new question.
    static func normalizedWords(_ text: String) -> [String] {
        var words: [String] = []
        var current = ""
        for ch in text.lowercased() {
            if ch.isNumber {
                if current != "#" {
                    if !current.isEmpty { words.append(current) }
                    current = "#"
                }
            } else if ch.isLetter {
                if current == "#" { words.append(current); current = "" }
                current.append(ch)
            } else if !current.isEmpty {
                words.append(current)
                current = ""
            }
        }
        if !current.isEmpty { words.append(current) }
        return words
    }

    static func fnv1a64(_ bytes: [UInt8]) -> UInt64 {
        var h: UInt64 = 0xcbf2_9ce4_8422_2325
        for b in bytes {
            h ^= UInt64(b)
            h = h &* 0x0000_0100_0000_01b3   // FNV prime; wrapping multiply is the algorithm
        }
        return h
    }
}

// MARK: - Features and scoring

/// One served request, as the detector remembers it. No prompt text.
public struct Observation: Sendable, Equatable {
    public let at: Millis
    public let shape: UInt64
    public let promptTokens: Int
    public let outputTokens: Int
    public let maxOutputTokens: Int
    public let refused: Bool

    public init(at: Millis, shape: UInt64, promptTokens: Int, outputTokens: Int, maxOutputTokens: Int, refused: Bool) {
        self.at = at
        self.shape = shape
        self.promptTokens = max(0, promptTokens)
        self.outputTokens = max(0, outputTokens)
        self.maxOutputTokens = max(0, maxOutputTokens)
        self.refused = refused
    }

    /// The completion ran into the cap the client asked for (>= 90% of it).
    /// People's answers usually end on their own; harvesting asks for the
    /// longest completion it can get and fills it.
    public var saturated: Bool {
        maxOutputTokens > 0 && Saturating.multiply(outputTokens, 10) >= Saturating.multiply(maxOutputTokens, 9)
    }
}

public enum Feature: String, CaseIterable, Sendable, Hashable {
    /// Share of prompts unlike every earlier prompt in the window. People
    /// iterate on a question; a distillation sweep covers new ground every call.
    case novelty
    /// How machine-regular the gaps between requests are.
    case cadence
    /// Share of completions that ran into the requested length cap. A raw
    /// output/prompt ratio was rejected: short questions with long answers are
    /// what ordinary chat looks like.
    case lengthSaturation
    /// Share of requests the model refused: probing for the policy boundary.
    case refusalProbing
    /// Sustained request rate.
    case volume
}

/// A linear ramp from "looks human" (0 points) to "looks scripted" (full weight).
/// `zeroAt` may be above `fullAt` for features where lower is worse (cadence).
public struct FeatureRamp: Sendable, Equatable {
    public let weight: Int
    public let zeroAt: Int
    public let fullAt: Int

    public init(weight: Int, zeroAt: Int, fullAt: Int) {
        self.weight = max(0, weight)
        self.zeroAt = zeroAt
        self.fullAt = fullAt
    }

    public func points(for value: Int) -> Int {
        guard zeroAt != fullAt else { return value >= fullAt ? weight : 0 }
        let rising = fullAt > zeroAt
        let progressed = rising ? Saturating.subtract(value, zeroAt) : Saturating.subtract(zeroAt, value)
        let span = rising ? Saturating.subtract(fullAt, zeroAt) : Saturating.subtract(zeroAt, fullAt)
        if progressed <= 0 { return 0 }
        if progressed >= span { return weight }
        // 0 < progressed < span, and weight is a small policy constant.
        return Saturating.divide(Saturating.multiply(weight, progressed), span) ?? 0
    }
}

public struct DetectorPolicy: Sendable {
    /// Observations kept per principal (a ring; memory is bounded by this).
    public var windowSize: Int
    /// Below this many observations the score is 0. Cold start is the price of
    /// not flagging new users on thin evidence; budgets cap what it costs.
    public var minSamples: Int
    /// Hamming distance above which a prompt counts as novel.
    public var noveltyDistance: Int
    public var ramps: [Feature: FeatureRamp]
    public var maxTrackedPrincipals: Int

    public init(
        windowSize: Int = 48,
        minSamples: Int = 10,
        noveltyDistance: Int = 14,
        ramps: [Feature: FeatureRamp] = DetectorPolicy.defaultRamps,
        maxTrackedPrincipals: Int = 50_000
    ) {
        self.windowSize = max(2, windowSize)
        self.minSamples = Saturating.clamp(minSamples, 2, self.windowSize)
        self.noveltyDistance = Saturating.clamp(noveltyDistance, 0, 64)
        self.ramps = ramps
        self.maxTrackedPrincipals = max(1, maxTrackedPrincipals)
    }

    /// Weights sum to 100. Values are permille except volume (requests per hour).
    public static let defaultRamps: [Feature: FeatureRamp] = [
        .novelty: FeatureRamp(weight: 30, zeroAt: 550, fullAt: 950),
        .cadence: FeatureRamp(weight: 25, zeroAt: 450, fullAt: 120),
        .lengthSaturation: FeatureRamp(weight: 20, zeroAt: 150, fullAt: 600),
        .refusalProbing: FeatureRamp(weight: 10, zeroAt: 30, fullAt: 150),
        .volume: FeatureRamp(weight: 15, zeroAt: 40, fullAt: 240),
    ]
}

public struct FeatureVector: Sendable, Equatable {
    public var noveltyPermille = 0
    /// Mean absolute deviation of inter-arrival gaps over their mean, permille.
    /// Low means regular.
    public var cadenceIrregularityPermille = 0
    public var lengthSaturationPermille = 0
    public var refusalPermille = 0
    public var requestsPerHour = 0

    public func value(_ feature: Feature) -> Int {
        switch feature {
        case .novelty: return noveltyPermille
        case .cadence: return cadenceIrregularityPermille
        case .lengthSaturation: return lengthSaturationPermille
        case .refusalProbing: return refusalPermille
        case .volume: return requestsPerHour
        }
    }
}

/// An explainable score: every point is attributed to a named feature, so a
/// support engineer can tell a user why they were asked to verify.
public struct RiskAssessment: Sendable, Equatable {
    public let score: Int
    public let samples: Int
    public let features: FeatureVector
    public let contributions: [Feature: Int]

    public static let empty = RiskAssessment(score: 0, samples: 0, features: FeatureVector(), contributions: [:])
}

/// Scores a window of observations. Pure: the same window always scores the same.
public struct ExtractionScorer: Sendable {
    public let policy: DetectorPolicy

    public init(policy: DetectorPolicy) { self.policy = policy }

    public func features(_ unordered: [Observation]) -> FeatureVector {
        var f = FeatureVector()
        // Observations are appended in completion order but stamped with arrival
        // time, so overlapping requests can arrive out of order. Time-based
        // features need them sorted by arrival.
        let window = unordered.sorted { $0.at < $1.at }
        let n = window.count
        guard n >= 2 else { return f }

        // Novelty: O(n^2) Hamming comparisons on a window of at most `windowSize`.
        var novel = 0
        for i in 1..<n {
            var nearest = 64
            for j in 0..<i {
                nearest = min(nearest, PromptShape.distance(window[i].shape, window[j].shape))
            }
            if nearest > policy.noveltyDistance { novel += 1 }
        }
        f.noveltyPermille = Saturating.divide(Saturating.multiply(novel, 1000), n - 1) ?? 0

        // Cadence: gaps between consecutive arrivals (negative gaps from a
        // misbehaving clock count as 0).
        var gaps: [Int] = []
        gaps.reserveCapacity(n - 1)
        for i in 1..<n { gaps.append(max(0, Saturating.subtract(window[i].at, window[i - 1].at))) }
        let gapSum = gaps.reduce(0) { Saturating.add($0, $1) }
        let mean = Saturating.divide(gapSum, gaps.count) ?? 0
        if mean > 0 {
            let deviation = gaps.reduce(0) { Saturating.add($0, abs(Saturating.subtract($1, mean))) }
            let mad = Saturating.divide(deviation, gaps.count) ?? 0
            f.cadenceIrregularityPermille = Saturating.divide(Saturating.multiply(mad, 1000), mean) ?? 0
        } // mean == 0: a burst in one millisecond is perfectly regular -> 0.

        let saturated = window.filter(\.saturated).count
        f.lengthSaturationPermille = Saturating.divide(Saturating.multiply(saturated, 1000), n) ?? 0

        let refused = window.filter(\.refused).count
        f.refusalPermille = Saturating.divide(Saturating.multiply(refused, 1000), n) ?? 0

        // first/last exist: n >= 2.
        let span = Saturating.subtract(window[n - 1].at, window[0].at)
        f.requestsPerHour = span > 0
            ? (Saturating.divide(Saturating.multiply(n - 1, 3_600_000), span) ?? Int.max)
            : Int.max
        return f
    }

    public func assess(_ window: [Observation]) -> RiskAssessment {
        guard window.count >= policy.minSamples else {
            return RiskAssessment(score: 0, samples: window.count, features: features(window), contributions: [:])
        }
        let f = features(window)
        var contributions: [Feature: Int] = [:]
        var score = 0
        for feature in Feature.allCases {
            guard let ramp = policy.ramps[feature] else { continue }
            let points = ramp.points(for: f.value(feature))
            contributions[feature] = points
            score = Saturating.add(score, points)
        }
        return RiskAssessment(
            score: Saturating.clamp(score, 0, 100),
            samples: window.count,
            features: f,
            contributions: contributions
        )
    }
}

// MARK: - Enforcement

public enum EnforcementLevel: Int, Comparable, Sendable, CaseIterable, CustomStringConvertible {
    case allow
    /// Next request must carry a fresh user verification (a passkey assertion
    /// with the user-verified flag). Costs a person a glance; costs a farm a human.
    case stepUp
    /// At most one request per `throttleIntervalMs`.
    case throttle
    /// Sticky until an operator clears it.
    case block

    public static func < (l: Self, r: Self) -> Bool { l.rawValue < r.rawValue }

    public var description: String {
        switch self {
        case .allow: return "allow"
        case .stepUp: return "step-up"
        case .throttle: return "throttle"
        case .block: return "block"
        }
    }
}

public struct EnforcementPolicy: Sendable {
    public var stepUpAt: Int
    public var throttleAt: Int
    public var blockAt: Int
    /// A level is left only once the score is this far below its threshold.
    public var hysteresis: Int
    /// ...and has been held at least this long.
    public var minHoldMs: Millis
    /// After a successful step-up, how long before another is demanded.
    public var stepUpGraceMs: Millis
    public var throttleIntervalMs: Millis

    public init(
        stepUpAt: Int = 40,
        throttleAt: Int = 60,
        blockAt: Int = 80,
        hysteresis: Int = 10,
        minHoldMs: Millis = 15 * 60_000,
        stepUpGraceMs: Millis = 30 * 60_000,
        throttleIntervalMs: Millis = 60_000
    ) {
        // Keep thresholds ordered whatever was passed in.
        self.stepUpAt = Saturating.clamp(stepUpAt, 1, 100)
        self.throttleAt = Saturating.clamp(throttleAt, self.stepUpAt, 100)
        self.blockAt = Saturating.clamp(blockAt, self.throttleAt, 100)
        self.hysteresis = max(0, hysteresis)
        self.minHoldMs = max(0, minHoldMs)
        self.stepUpGraceMs = max(0, stepUpGraceMs)
        self.throttleIntervalMs = max(1, throttleIntervalMs)
    }

    func target(for score: Int) -> EnforcementLevel {
        if score >= blockAt { return .block }
        if score >= throttleAt { return .throttle }
        if score >= stepUpAt { return .stepUp }
        return .allow
    }

    func threshold(of level: EnforcementLevel) -> Int {
        switch level {
        case .allow: return 0
        case .stepUp: return stepUpAt
        case .throttle: return throttleAt
        case .block: return blockAt
        }
    }

    /// Escalate at once; de-escalate one level at a time, with hysteresis and a
    /// minimum hold, so a score hovering on a threshold cannot flap. Block never
    /// de-escalates on its own.
    public func next(current: EnforcementLevel, since: Millis, score: Int, now: Millis) -> EnforcementLevel {
        let target = target(for: score)
        if target > current { return current == .block ? .block : target }
        guard current != .block, target < current else { return current }
        let held = Saturating.subtract(now, since)
        guard held >= minHoldMs, score < Saturating.subtract(threshold(of: current), hysteresis) else { return current }
        return EnforcementLevel(rawValue: current.rawValue - 1) ?? .allow
    }
}
