import Foundation   // NSLock only

/// Simulation building blocks for the lab, previews and tests. Nothing here is
/// production code: the signature and user-verification schemes are stand-ins.

/// A small lock-protected box. `@unchecked Sendable` is sound because every
/// access to `value` goes through `lock`.
final class Locked<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Value
    init(_ value: Value) { self.value = value }
    func withValue<R>(_ body: (inout Value) -> R) -> R {
        lock.lock()
        defer { lock.unlock() }
        return body(&value)
    }
}

/// A clock the lab moves by hand.
public final class ManualClock: GatewayClock, @unchecked Sendable {
    private let state: Locked<Millis>
    public init(start: Millis = 0) { state = Locked(start) }
    public func now() -> Millis { state.withValue { $0 } }
    public func set(_ t: Millis) { state.withValue { $0 = t } }
    public func advance(by ms: Millis) { state.withValue { $0 = Saturating.add($0, max(0, ms)) } }
}

/// SplitMix64: tiny, fast, and the same sequence on every platform.
public struct SeededGenerator: RandomNumberGenerator, Sendable {
    private var state: UInt64
    public init(seed: UInt64) { state = seed }
    public mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

/// Deterministic challenges, so a lab run is reproducible.
public final class SeededEntropy: ChallengeEntropy, @unchecked Sendable {
    private let rng: Locked<SeededGenerator>
    public init(seed: UInt64) { rng = Locked(SeededGenerator(seed: seed)) }
    public func challengeBytes() -> [UInt8] {
        rng.withValue { g in (0..<16).map { _ in UInt8.random(in: .min ... .max, using: &g) } }
    }
}

/// A simulated App Attest key: the counter lives "in the enclave" (here, behind
/// a lock) and increments on every assertion, exactly like the real one.
public final class SimulatedDevice: DeviceAttester, @unchecked Sendable {
    public let keyID: DeviceKeyID
    public let secret: [UInt8]
    private let counter: Locked<UInt32>

    public convenience init(keyID: DeviceKeyID, secret: [UInt8]) {
        self.init(keyID: keyID, secret: secret, startingCounter: 0)
    }

    /// For tests: start the enclave counter somewhere other than 0.
    init(keyID: DeviceKeyID, secret: [UInt8], startingCounter: UInt32) {
        self.keyID = keyID
        self.secret = secret
        self.counter = Locked(startingCounter)
    }

    public var currentCounter: UInt32 { counter.withValue { $0 } }

    public func assert(clientDataHash: SHA256Digest) async -> Assertion? {
        let next: UInt32? = counter.withValue { c in
            guard c < UInt32.max else { return nil }   // key exhausted: re-attest
            c += 1
            return c
        }
        guard let next else { return nil }
        return makeAssertion(counter: next, clientDataHash: clientDataHash)
    }

    /// Signs with an explicit counter. Lets tests and the lab build out-of-order
    /// or replayed assertions.
    public func makeAssertion(counter: UInt32, clientDataHash: SHA256Digest) -> Assertion {
        let message = Assertion.signedMessage(counter: counter, clientDataHash: clientDataHash)
        return Assertion(
            keyID: keyID, counter: counter, clientDataHash: clientDataHash,
            signature: InsecureSimulatedSignature.sign(message, secret: secret)
        )
    }
}

/// Stand-in for a passkey assertion with the user-verified flag: a keyed hash
/// over (principal, challenge), so a proof is good for one challenge only.
public struct SimulatedUserVerification: UserVerificationVerifier, UserVerifying {
    public init() {}

    public static func makeProof(principal: PrincipalID, challenge: [UInt8]) -> UserVerificationProof {
        var w = CanonicalWriter(domain: "gateway-shield/v1/simulated-uv")
        w.field(Array(principal.rawValue.utf8))
        w.field(challenge)
        return UserVerificationProof(bytes: SHA256.hash(w.bytes).bytes)
    }

    public func verify(_ proof: UserVerificationProof, principal: PrincipalID, challenge: [UInt8]) -> Bool {
        Self.makeProof(principal: principal, challenge: challenge) == proof
    }

    public func proof(principal: PrincipalID, challenge: [UInt8]) async -> UserVerificationProof? {
        Self.makeProof(principal: principal, challenge: challenge)
    }
}

/// Stand-in for the app's session tokens: a keyed hash of the principal under a
/// server secret, so a client can present its own token but cannot mint one for
/// somebody else.
public struct SimulatedSessions: SessionAuthenticator {
    private let serverSecret: [UInt8]
    public init(serverSecret: [UInt8]) { self.serverSecret = serverSecret }

    public func issue(for principal: PrincipalID) -> [UInt8] {
        var w = CanonicalWriter(domain: "gateway-shield/v1/simulated-session")
        w.field(serverSecret)
        w.field(Array(principal.rawValue.utf8))
        return SHA256.hash(w.bytes).bytes
    }

    public func authenticates(_ session: [UInt8], as principal: PrincipalID, now: Millis) -> Bool {
        issue(for: principal) == session
    }
}

/// A deterministic fake model.
///
/// - Prompts containing `[restricted]` are refused (40 tokens).
/// - Prompts asking for "exhaustive detail" fill the requested cap.
/// - Everything else gets 120...599 tokens, capped at the request's limit.
///
/// `latencyMs` advances the shared clock; `yields` hands the executor to other
/// tasks mid-call, which is what makes the concurrency tests interleave.
public final class SimulatedModel: UpstreamModel, @unchecked Sendable {
    private let clock: ManualClock?
    private let latencyMs: Millis
    private let yields: Int
    private let counters = Locked((current: 0, peak: 0, calls: 0))

    public init(clock: ManualClock? = nil, latencyMs: Millis = 0, yields: Int = 0) {
        self.clock = clock
        self.latencyMs = max(0, latencyMs)
        self.yields = max(0, yields)
    }

    /// Highest number of calls that were inside `complete` at the same time.
    public var peakConcurrency: Int { counters.withValue { $0.peak } }
    public var calls: Int { counters.withValue { $0.calls } }

    public func complete(_ payload: PromptPayload) async -> UpstreamResult {
        counters.withValue { c in
            c.current += 1
            c.calls += 1
            c.peak = max(c.peak, c.current)
        }
        for _ in 0..<yields { await Task.yield() }
        if latencyMs > 0 { clock?.advance(by: latencyMs) }
        counters.withValue { $0.current -= 1 }
        return Self.respond(to: payload)
    }

    /// The fake vendor's own input count: one token per 4 UTF-8 bytes.
    public static func vendorInputTokens(_ prompt: String) -> Int {
        max(1, Saturating.ceilDivide(prompt.utf8.count, 4) ?? 1)
    }

    public static func respond(to payload: PromptPayload) -> UpstreamResult {
        let cap = max(0, payload.maxOutputTokens)
        let input = vendorInputTokens(payload.prompt)
        if payload.prompt.contains("[restricted]") {
            return .completed(inputTokens: input, outputTokens: min(40, cap), refused: true)
        }
        if payload.prompt.lowercased().contains("exhaustive detail") {
            return .completed(inputTokens: input, outputTokens: cap, refused: false)
        }
        let h = PromptShape.fnv1a64(Array(payload.prompt.utf8))
        let natural = 120 + Int(h % 480)   // h % 480 < 480: fits any Int
        return .completed(inputTokens: input, outputTokens: min(natural, cap), refused: false)
    }
}
