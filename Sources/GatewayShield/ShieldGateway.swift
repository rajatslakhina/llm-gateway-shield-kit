// MARK: - Ports

public protocol GatewayClock: Sendable {
    func now() -> Millis
}

public protocol ChallengeEntropy: Sendable {
    func challengeBytes() -> [UInt8]
}

/// 16 bytes from the system CSPRNG.
public struct SystemEntropy: ChallengeEntropy {
    public init() {}
    public func challengeBytes() -> [UInt8] {
        var rng = SystemRandomNumberGenerator()
        return (0..<16).map { _ in UInt8.random(in: .min ... .max, using: &rng) }
    }
}

/// The gateway never trusts a client's token count; it estimates its own.
public protocol TokenEstimator: Sendable {
    func estimate(_ prompt: String) -> Int
}

/// A deliberately pessimistic estimate: the larger of ~4/3 tokens per word and
/// one token per 4 UTF-8 bytes, at least 1. The byte bound matters: a prompt
/// with no spaces (`"x,x,x,..."`) is one "word" but thousands of tokens.
/// Production: the vendor's tokenizer or its count-tokens endpoint. Whatever the
/// estimate, settle reconciles against the vendor's reported input count.
public struct WordTokenEstimator: TokenEstimator {
    public init() {}
    public func estimate(_ prompt: String) -> Int {
        let words = prompt.split(whereSeparator: { $0 == " " || $0 == "\n" || $0 == "\t" }).count
        let byWords = Saturating.ceilDivide(Saturating.multiply(words, 4), 3) ?? 1
        let byBytes = Saturating.ceilDivide(prompt.utf8.count, 4) ?? 1
        return max(1, byWords, byBytes)
    }
}

/// Answers "does this session credential belong to this principal?".
///
/// The principal named in a request is client-supplied. The device assertion
/// proves only that *some* attested install signed a request naming it, so
/// without this check any attested phone could spend, or get blocked, someone
/// else's account. Production: verify the app's session token (a signed JWT
/// or an opaque token looked up server-side).
public protocol SessionAuthenticator: Sendable {
    func authenticates(_ session: [UInt8], as principal: PrincipalID, now: Millis) -> Bool
}

public enum UpstreamResult: Equatable, Sendable {
    /// `inputTokens` is the vendor's own count when it reports one. Settle charges
    /// the larger of it and the gateway's estimate, so an estimate that was too
    /// low can't be exploited.
    case completed(inputTokens: Int?, outputTokens: Int, refused: Bool)
    /// `tokensConsumed == nil` means the gateway cannot know (a timeout after the
    /// vendor may have started generating), so the full reservation is charged.
    case failed(tokensConsumed: Int?)
}

/// The model vendor behind the gateway.
public protocol UpstreamModel: Sendable {
    func complete(_ payload: PromptPayload) async -> UpstreamResult
}

/// Proof that a person was present for this request: production would verify a
/// passkey (WebAuthn) assertion with the user-verified flag over the challenge.
/// App Attest alone cannot prove this; it attests the app and device, not a user.
public struct UserVerificationProof: Hashable, Sendable {
    public let bytes: [UInt8]
    public init(bytes: [UInt8]) { self.bytes = bytes }
}

public protocol UserVerificationVerifier: Sendable {
    func verify(_ proof: UserVerificationProof, principal: PrincipalID, challenge: [UInt8]) -> Bool
}

// MARK: - Requests and responses

public struct GatewayRequest: Sendable {
    public let principal: PrincipalID
    /// The app's session credential for `principal`.
    public let session: [UInt8]
    public let path: String
    public let payload: PromptPayload
    public let challenge: [UInt8]
    public let assertion: Assertion
    public let userVerification: UserVerificationProof?

    public init(
        principal: PrincipalID, session: [UInt8], path: String, payload: PromptPayload, challenge: [UInt8],
        assertion: Assertion, userVerification: UserVerificationProof? = nil
    ) {
        self.principal = principal
        self.session = session
        self.path = path
        self.payload = payload
        self.challenge = challenge
        self.assertion = assertion
        self.userVerification = userVerification
    }
}

public enum Rejection: Equatable, Sendable {
    case challenge(ChallengeVerdict)
    case unauthenticated
    case assertion(AssertionVerdict)
    case invalidPayload
    case stepUpRequired
    case throttled(retryAfterMs: Millis)
    case blocked
    case budget(BudgetDenial)
    case capacity
    case upstreamFailed

    /// Stable label for counters and dashboards.
    public var label: String {
        switch self {
        case .challenge: return "challenge"
        case .unauthenticated: return "unauthenticated"
        case .assertion(.replayed): return "replay"
        case .assertion(.badSignature): return "bad-signature"
        case .assertion(.bindingMismatch): return "binding-mismatch"
        case .assertion(.accountLimitExceeded): return "account-limit"
        case .assertion(.revokedKey): return "revoked-key"
        case .assertion: return "unknown-key"
        case .invalidPayload: return "invalid-payload"
        case .stepUpRequired: return "step-up"
        case .throttled: return "throttled"
        case .blocked: return "blocked"
        case .budget(.tooManyInFlight): return "in-flight-limit"
        case .budget: return "budget"
        case .capacity: return "capacity"
        case .upstreamFailed: return "upstream-failed"
        }
    }
}

public enum GatewayOutcome: Equatable, Sendable {
    case served(outputTokens: Int, refused: Bool)
    case rejected(Rejection)
}

public struct GatewayResponse: Equatable, Sendable {
    public let outcome: GatewayOutcome
    public let level: EnforcementLevel
    public let risk: Int
    /// The principal's remaining tokens; `nil` when the request was rejected
    /// before the principal was authenticated (never leak budgets to strangers).
    public let remainingTokens: Int?
}

public struct GatewayConfiguration: Sendable {
    public var challengeTTL: Millis
    public var challengeCapacity: Int
    public var maxAccountsPerKey: Int
    public var maxKeys: Int
    public var maxOutputTokensCap: Int
    /// Prompts above this many UTF-8 bytes are refused before anything hashes
    /// them. (Production also caps the body at the HTTP layer.)
    public var maxPromptBytes: Int
    public var budget: BudgetPolicy
    public var detector: DetectorPolicy
    public var enforcement: EnforcementPolicy

    public init(
        challengeTTL: Millis, challengeCapacity: Int, maxAccountsPerKey: Int, maxKeys: Int,
        maxOutputTokensCap: Int, maxPromptBytes: Int = 32_768,
        budget: BudgetPolicy, detector: DetectorPolicy, enforcement: EnforcementPolicy
    ) {
        self.challengeTTL = challengeTTL
        self.challengeCapacity = challengeCapacity
        self.maxAccountsPerKey = maxAccountsPerKey
        self.maxKeys = maxKeys
        self.maxOutputTokensCap = max(1, maxOutputTokensCap)
        self.maxPromptBytes = max(1, maxPromptBytes)
        self.budget = budget
        self.detector = detector
        self.enforcement = enforcement
    }

    /// The defaults the README and the lab use.
    public static var standard: GatewayConfiguration {
        let day: Millis = 86_400_000
        return GatewayConfiguration(
            challengeTTL: 60_000,
            challengeCapacity: 10_000,
            maxAccountsPerKey: 3,
            maxKeys: 1_000_000,
            maxOutputTokensCap: 4_096,
            budget: BudgetPolicy(
                perPrincipal: .clamped(tokens: 60_000, windowMs: day),
                perDevice: .clamped(tokens: 120_000, windowMs: day),
                global: .clamped(tokens: 20_000_000, windowMs: 3_600_000),
                maxInFlightPerPrincipal: 4,
                reservationTTL: 120_000,
                maxOutstandingReservations: 50_000,
                maxTrackedBuckets: 200_000
            ),
            detector: DetectorPolicy(),
            enforcement: EnforcementPolicy()
        )
    }
}

public struct IssuedChallenge: Hashable, Sendable {
    public let bytes: [UInt8]
    public let expiresAt: Millis
}

public struct PrincipalSnapshot: Sendable, Equatable {
    public let principal: PrincipalID
    public let level: EnforcementLevel
    public let assessment: RiskAssessment
    public let remainingTokens: Int
    public let served: Int
}

public struct GatewayStats: Sendable, Equatable {
    public var received = 0
    public var served = 0
    public var rejections: [String: Int] = [:]
    public var tokensServed = 0
    /// Highest number of unsettled reservations any one principal held.
    public var peakInFlightPerPrincipal = 0
}

// MARK: - Gateway

/// The server half: an abuse-resistant proxy between an iOS app and an LLM vendor.
///
/// Pipeline per request, cheapest and least-trusting check first:
/// 1. single-use challenge (and a prompt-size cap),
/// 2. session check (the named principal is the session's), then an App Attest-shaped assertion bound to this exact request (replay window,
///    signature, account-per-device limit),
/// 3. enforcement level (block / throttle / step-up),
/// 4. budget reservation across principal, device and fleet,
/// 5. upstream call (the only suspension point),
/// 6. settle, observe, re-score.
///
/// Actor reentrancy: steps 1-4 run without suspending, so no other request can
/// interleave between a check and the state change it guards. Everything after
/// the `await` re-reads state instead of trusting values captured before it.
public actor ShieldGateway {
    struct PrincipalState {
        var window: [Observation] = []
        var level: EnforcementLevel = .allow
        var levelSince: Millis
        var stepUpGraceUntil: Millis = Int.min
        var lastServedAt: Millis?
        var lastSeen: Millis
        var assessment: RiskAssessment = .empty
        var served = 0
    }

    public let configuration: GatewayConfiguration
    private let clock: any GatewayClock
    private let entropy: any ChallengeEntropy
    private let estimator: any TokenEstimator
    private let upstream: any UpstreamModel
    private let signatureVerifier: any AssertionSignatureVerifier
    private let userVerifier: any UserVerificationVerifier
    private let sessions: any SessionAuthenticator
    private let scorer: ExtractionScorer

    private var challenges: ChallengeStore
    private var keys: KeyRegistry
    private var ledger: BudgetLedger
    private var principals: [PrincipalID: PrincipalState] = [:]
    public private(set) var stats = GatewayStats()

    public init(
        configuration: GatewayConfiguration,
        clock: any GatewayClock,
        entropy: any ChallengeEntropy = SystemEntropy(),
        estimator: any TokenEstimator = WordTokenEstimator(),
        upstream: any UpstreamModel,
        signatureVerifier: any AssertionSignatureVerifier,
        userVerifier: any UserVerificationVerifier,
        sessions: any SessionAuthenticator
    ) {
        self.configuration = configuration
        self.clock = clock
        self.entropy = entropy
        self.estimator = estimator
        self.upstream = upstream
        self.signatureVerifier = signatureVerifier
        self.userVerifier = userVerifier
        self.sessions = sessions
        self.scorer = ExtractionScorer(policy: configuration.detector)
        self.challenges = ChallengeStore(ttl: configuration.challengeTTL, capacity: configuration.challengeCapacity)
        self.keys = KeyRegistry(maxAccountsPerKey: configuration.maxAccountsPerKey, maxKeys: configuration.maxKeys)
        self.ledger = BudgetLedger(policy: configuration.budget)
    }

    // MARK: Admin surface

    public func register(_ keyID: DeviceKeyID, publicKey: [UInt8]) -> RegistrationResult {
        keys.register(keyID, publicKey: publicKey)
    }

    public func revoke(_ keyID: DeviceKeyID) { keys.revoke(keyID) }

    /// Operator action: the only way out of `.block`.
    public func unblock(_ principal: PrincipalID) {
        guard var state = principals[principal] else { return }
        state.level = .allow
        state.levelSince = clock.now()
        state.window.removeAll()
        state.assessment = .empty
        principals[principal] = state
    }

    public func issueChallenge() -> IssuedChallenge {
        let bytes = entropy.challengeBytes()
        let expiresAt = challenges.insert(bytes, now: clock.now())
        return IssuedChallenge(bytes: bytes, expiresAt: expiresAt)
    }

    public func snapshot(_ principal: PrincipalID) -> PrincipalSnapshot {
        let state = principals[principal]
        return PrincipalSnapshot(
            principal: principal,
            level: state?.level ?? .allow,
            assessment: state?.assessment ?? .empty,
            remainingTokens: ledger.remaining(.principal(principal), now: clock.now()),
            served: state?.served ?? 0
        )
    }

    public var outstandingReservations: Int { ledger.outstandingReservations }
    public func inFlight(_ principal: PrincipalID) -> Int { ledger.inFlight(for: principal) }
    public func remaining(_ scope: BudgetScope) -> Int { ledger.remaining(scope, now: clock.now()) }

    // MARK: Request path

    public func handle(_ request: GatewayRequest) async -> GatewayResponse {
        let now = clock.now()
        stats.received += 1
        let principal = request.principal

        // 1. Challenge: consumed whatever happens next.
        let challengeVerdict = challenges.consume(request.challenge, now: now)
        guard challengeVerdict == .fresh else { return reject(.challenge(challengeVerdict), principal: nil) }

        // Size before anything hashes or scans the prompt.
        guard request.payload.prompt.utf8.count <= configuration.maxPromptBytes else {
            return reject(.invalidPayload, principal: nil)
        }

        // 2a. The principal must be the session's, not just a name the client typed.
        guard sessions.authenticates(request.session, as: principal, now: now) else {
            return reject(.unauthenticated, principal: nil)
        }

        // 2b. Assertion bound to (challenge, principal, path, payload).
        let expected = RequestBinding.clientDataHash(
            challenge: request.challenge, principal: principal, path: request.path, payload: request.payload
        )
        let verdict = keys.verify(
            request.assertion, expectedClientDataHash: expected, principal: principal, verifier: signatureVerifier
        )
        guard verdict == .accepted else { return reject(.assertion(verdict), principal: nil) }

        let maxOut = request.payload.maxOutputTokens
        guard maxOut > 0, maxOut <= configuration.maxOutputTokensCap else {
            return reject(.invalidPayload, principal: principal)
        }

        // 3. Enforcement.
        guard var state = admit(principal, now: now) else { return reject(.capacity, principal: principal) }
        state.lastSeen = now
        let policy = configuration.enforcement
        switch state.level {
        case .block:
            principals[principal] = state
            return reject(.blocked, principal: principal)
        case .throttle:
            if let last = state.lastServedAt {
                let wait = Saturating.subtract(Saturating.add(last, policy.throttleIntervalMs), now)
                if wait > 0 {
                    principals[principal] = state
                    return reject(.throttled(retryAfterMs: wait), principal: principal)
                }
            }
            fallthrough   // throttled principals must also pass step-up
        case .stepUp:
            if now >= state.stepUpGraceUntil {
                guard let proof = request.userVerification,
                      userVerifier.verify(proof, principal: principal, challenge: request.challenge) else {
                    principals[principal] = state
                    return reject(.stepUpRequired, principal: principal)
                }
                state.stepUpGraceUntil = Saturating.add(now, policy.stepUpGraceMs)
            }
        case .allow:
            break
        }

        // 4. Budget: reserve the worst case now, refund at settle.
        let promptTokens = estimator.estimate(request.payload.prompt)
        let cost = Saturating.add(promptTokens, maxOut)
        let reservation: Reservation
        switch ledger.reserve(tokens: cost, principal: principal, device: request.assertion.keyID, now: now) {
        case .success(let r):
            reservation = r
            stats.peakInFlightPerPrincipal = max(stats.peakInFlightPerPrincipal, ledger.inFlight(for: principal))
        case .failure(let denial):
            principals[principal] = state
            return reject(.budget(denial), principal: principal)
        }
        // Stamp before suspending so a concurrent request from a throttled
        // principal sees this one.
        state.lastServedAt = now
        principals[principal] = state

        // 5. The only suspension point.
        let result = await upstream.complete(request.payload)

        // 6. Re-read everything: other requests ran while we were suspended.
        let done = clock.now()
        switch result {
        case .completed(let reportedInput, let outputTokens, let refused):
            let output = max(0, outputTokens)
            let input = max(promptTokens, reportedInput ?? 0)
            _ = ledger.settle(reservation.id, actualTokens: Saturating.add(input, output), now: done)
            observe(principal, Observation(
                at: now, shape: PromptShape.simHash(request.payload.prompt),
                promptTokens: input, outputTokens: output, maxOutputTokens: maxOut, refused: refused
            ), now: done)
            stats.served += 1
            stats.tokensServed = Saturating.add(stats.tokensServed, output)
            let current = principals[principal]
            return GatewayResponse(
                outcome: .served(outputTokens: output, refused: refused),
                level: current?.level ?? .allow,
                risk: current?.assessment.score ?? 0,
                remainingTokens: ledger.remaining(.principal(principal), now: done)
            )
        case .failed(let consumed):
            let charge = consumed.map { Saturating.add(promptTokens, max(0, $0)) } ?? reservation.tokens
            _ = ledger.settle(reservation.id, actualTokens: charge, now: done)
            return reject(.upstreamFailed, principal: principal)
        }
    }

    // MARK: Internals

    private func reject(_ rejection: Rejection, principal: PrincipalID?) -> GatewayResponse {
        stats.rejections[rejection.label, default: 0] += 1
        guard let principal else {
            return GatewayResponse(outcome: .rejected(rejection), level: .allow, risk: 0, remainingTokens: nil)
        }
        let state = principals[principal]
        return GatewayResponse(
            outcome: .rejected(rejection),
            level: state?.level ?? .allow,
            risk: state?.assessment.score ?? 0,
            remainingTokens: ledger.remaining(.principal(principal), now: clock.now())
        )
    }

    /// Fetches or creates the principal's state within the memory bound.
    ///
    /// When full, the least recently seen principal at `.allow` is forgotten. That
    /// can drop up to a full observation window for an account scoring just
    /// below step-up, so it restarts its evidence; it never drops a flag. If
    /// every tracked principal is flagged, new principals are refused rather than
    /// letting a flood of fresh accounts evict the flags.
    private func admit(_ principal: PrincipalID, now: Millis) -> PrincipalState? {
        if let state = principals[principal] { return state }
        if principals.count >= configuration.detector.maxTrackedPrincipals {
            let victim = principals
                .filter { $0.value.level == .allow }
                .min { $0.value.lastSeen < $1.value.lastSeen }
            guard let victim else { return nil }
            principals[victim.key] = nil
        }
        let state = PrincipalState(levelSince: now, lastSeen: now)
        principals[principal] = state
        return state
    }

    private func observe(_ principal: PrincipalID, _ observation: Observation, now: Millis) {
        // The state may have been evicted while we were suspended; re-admit.
        guard var state = admit(principal, now: now) else { return }
        state.window.append(observation)
        let overflow = state.window.count - configuration.detector.windowSize
        if overflow > 0 { state.window.removeFirst(overflow) }
        state.served += 1
        state.assessment = scorer.assess(state.window)
        let next = configuration.enforcement.next(
            current: state.level, since: state.levelSince, score: state.assessment.score, now: now
        )
        if next != state.level {
            state.level = next
            state.levelSince = now
        }
        principals[principal] = state
    }
}
