/// The device side of App Attest: a Secure Enclave key that signs with a
/// counter it increments itself. The app never chooses the counter, which is
/// why two concurrent requests can reach the server out of order and why the
/// server keeps a replay *window* rather than a single "last counter".
public protocol DeviceAttester: Sendable {
    var keyID: DeviceKeyID { get }
    /// `nil` when the key is unusable (lost, invalidated by a restore, counter exhausted).
    func assert(clientDataHash: SHA256Digest) async -> Assertion?
}

/// Gets a person to verify (Face ID / passkey) for one challenge.
public protocol UserVerifying: Sendable {
    func proof(principal: PrincipalID, challenge: [UInt8]) async -> UserVerificationProof?
}

public protocol GatewayTransport: Sendable {
    func challenge() async -> [UInt8]
    func send(_ request: GatewayRequest) async -> GatewayResponse
}

public enum ClientResult: Equatable, Sendable {
    case completed(outputTokens: Int, refused: Bool)
    /// The gateway wants a person; there is no verifier, or the person declined.
    case needsUserVerification
    case retryAfter(Millis)
    case budgetExhausted(scope: BudgetScope?, retryAfterMs: Millis?)
    case blocked
    case attestationUnavailable
    case failed(Rejection)
}

/// The iOS-side client. It owns three decisions so feature code doesn't:
/// which rejections are worth an automatic retry (an expired or evicted
/// challenge, a first step-up demand), which go back to the UI (throttle,
/// budget, block), and how many attempts one call may make (at most 3, so a
/// misbehaving gateway can't turn one tap into a retry storm).
public actor GatewayClient {
    public nonisolated let principal: PrincipalID
    public nonisolated let path: String
    private let session: [UInt8]
    private let attester: any DeviceAttester
    private let transport: any GatewayTransport
    private let userVerifier: (any UserVerifying)?
    public private(set) var attempts = 0

    public static let maxAttemptsPerCall = 3

    public init(
        principal: PrincipalID,
        session: [UInt8],
        path: String = "/v1/complete",
        attester: any DeviceAttester,
        transport: any GatewayTransport,
        userVerifier: (any UserVerifying)?
    ) {
        self.principal = principal
        self.session = session
        self.path = path
        self.attester = attester
        self.transport = transport
        self.userVerifier = userVerifier
    }

    public func complete(_ payload: PromptPayload) async -> ClientResult {
        var includeVerification = false
        var lastRejection: Rejection = .upstreamFailed
        for _ in 0..<Self.maxAttemptsPerCall {
            attempts += 1
            let challenge = await transport.challenge()
            let hash = RequestBinding.clientDataHash(
                challenge: challenge, principal: principal, path: path, payload: payload
            )
            var proof: UserVerificationProof?
            if includeVerification {
                guard let verifier = userVerifier,
                      let p = await verifier.proof(principal: principal, challenge: challenge) else {
                    return .needsUserVerification
                }
                proof = p
            }
            guard let assertion = await attester.assert(clientDataHash: hash) else { return .attestationUnavailable }
            let response = await transport.send(GatewayRequest(
                principal: principal, session: session, path: path, payload: payload, challenge: challenge,
                assertion: assertion, userVerification: proof
            ))
            switch response.outcome {
            case .served(let output, let refused):
                return .completed(outputTokens: output, refused: refused)
            case .rejected(let rejection):
                lastRejection = rejection
                switch rejection {
                case .challenge:
                    continue   // stale or evicted challenge: one fresh attempt
                case .stepUpRequired:
                    if includeVerification || userVerifier == nil { return .needsUserVerification }
                    includeVerification = true
                    continue
                case .throttled(let wait):
                    return .retryAfter(wait)
                case .budget(.insufficient(let scope, let wait)):
                    return .budgetExhausted(scope: scope, retryAfterMs: wait)
                case .budget(.exceedsLimit(let scope)):
                    return .budgetExhausted(scope: scope, retryAfterMs: nil)
                case .budget(.tooManyInFlight):
                    return .retryAfter(1_000)
                case .budget:
                    return .budgetExhausted(scope: nil, retryAfterMs: nil)
                case .blocked:
                    return .blocked
                default:
                    return .failed(rejection)
                }
            }
        }
        return .failed(lastRejection)
    }
}

/// Calls a gateway in the same process (the lab, previews, tests).
public struct InProcessTransport: GatewayTransport {
    public let gateway: ShieldGateway
    public init(gateway: ShieldGateway) { self.gateway = gateway }
    public func challenge() async -> [UInt8] { await gateway.issueChallenge().bytes }
    public func send(_ request: GatewayRequest) async -> GatewayResponse { await gateway.handle(request) }
}
