@testable import GatewayShield

/// Builds a gateway on a manual clock with a deterministic challenge source.
struct Harness {
    let clock: ManualClock
    let model: SimulatedModel
    let gateway: ShieldGateway
    static let sessions = SimulatedSessions(serverSecret: [7, 7, 7])

    init(_ configuration: GatewayConfiguration = .standard, latencyMs: Millis = 0, yields: Int = 0,
         upstream: (any UpstreamModel)? = nil,
         verifier: any AssertionSignatureVerifier = InsecureSimulatedSignature()) {
        clock = ManualClock(start: 1_000_000)
        model = SimulatedModel(clock: clock, latencyMs: latencyMs, yields: yields)
        gateway = ShieldGateway(
            configuration: configuration, clock: clock, entropy: SeededEntropy(seed: 42),
            upstream: upstream ?? model, signatureVerifier: verifier, userVerifier: SimulatedUserVerification(),
            sessions: Harness.sessions
        )
    }

    func enroll(_ name: String) async -> SimulatedDevice {
        let secret = SHA256.hash(Array("secret:\(name)".utf8)).bytes
        let device = SimulatedDevice(keyID: DeviceKeyID("key-\(name)"), secret: secret)
        _ = await gateway.register(device.keyID, publicKey: secret)
        return device
    }

    /// A correctly signed request on a fresh challenge.
    func request(_ device: SimulatedDevice, _ principal: String, _ prompt: String = "how do i debounce search input",
                 maxOutput: Int = 256, counter: UInt32? = nil, withProof: Bool = false) async -> GatewayRequest {
        let p = PrincipalID(principal)
        let payload = PromptPayload(prompt: prompt, maxOutputTokens: maxOutput)
        let challenge = await gateway.issueChallenge().bytes
        let hash = RequestBinding.clientDataHash(challenge: challenge, principal: p, path: "/v1/complete", payload: payload)
        let assertion: Assertion
        if let counter {
            assertion = device.makeAssertion(counter: counter, clientDataHash: hash)
        } else {
            assertion = await device.assert(clientDataHash: hash) ?? device.makeAssertion(counter: 0, clientDataHash: hash)
        }
        return GatewayRequest(
            principal: p, session: Harness.sessions.issue(for: p), path: "/v1/complete", payload: payload, challenge: challenge, assertion: assertion,
            userVerification: withProof ? SimulatedUserVerification.makeProof(principal: p, challenge: challenge) : nil
        )
    }

    func send(_ device: SimulatedDevice, _ principal: String, _ prompt: String = "how do i debounce search input",
              maxOutput: Int = 256, withProof: Bool = false) async -> GatewayResponse {
        await gateway.handle(await request(device, principal, prompt, maxOutput: maxOutput, withProof: withProof))
    }
}

func isServed(_ r: GatewayResponse) -> Bool {
    if case .served = r.outcome { return true }
    return false
}

func limit(_ tokens: Int, _ windowMs: Millis) -> BudgetLimit { .clamped(tokens: tokens, windowMs: windowMs) }

/// A policy whose score is driven by volume alone, so tests can push a principal
/// to a chosen level with a handful of same-millisecond requests.
func volumeOnlyConfiguration(stepUpAt: Int = 40, throttleAt: Int = 60, blockAt: Int = 80, points: Int) -> GatewayConfiguration {
    var c = GatewayConfiguration.standard
    c.detector = DetectorPolicy(windowSize: 8, minSamples: 2, ramps: [.volume: FeatureRamp(weight: points, zeroAt: 0, fullAt: 1)])
    c.enforcement = EnforcementPolicy(stepUpAt: stepUpAt, throttleAt: throttleAt, blockAt: blockAt, hysteresis: 10,
                                      minHoldMs: 60_000, stepUpGraceMs: 300_000, throttleIntervalMs: 30_000)
    return c
}

/// Accepts any signature: used to show the signature check is load-bearing.
struct AcceptAnySignature: AssertionSignatureVerifier {
    func isValidSignature(_ signature: [UInt8], over message: [UInt8], publicKey: [UInt8]) -> Bool { true }
}
