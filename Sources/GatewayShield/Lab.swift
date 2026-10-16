/// A deterministic, virtual-time lab that drives a real `ShieldGateway` and real
/// `GatewayClient`s with simulated people, scrapers and attackers. The demo app
/// renders its reports; the tests assert on them.

public enum PersonaKind: String, Sendable, Equatable {
    case person = "Person"
    case powerUser = "Power user"
    case scraper = "Scraper"
    case attacker = "Attacker"

    public var isHuman: Bool { self == .person || self == .powerUser }
}

public enum LabScenario: String, CaseIterable, Sendable, Identifiable {
    case mixedDay = "Mixed day"
    case accountFarm = "Account farm"
    case fanOut = "Parallel fan-out"
    case forgery = "Replay & forgery"

    public var id: String { rawValue }

    public var summary: String {
        switch self {
        case .mixedDay:
            return "24 virtual hours: eight people (one a heavy power user, one who asks something new every time), a fast sweep scraper and a slower one that mimics human timing."
        case .accountFarm:
            return "One attested app install, five accounts, long completions on human-looking timing. Per-account signals stay quiet; the per-key limits do the work."
        case .fanOut:
            return "One account fires 60 requests in three concurrent waves against a 5,000-token budget."
        case .forgery:
            return "Captured requests replayed, a tampered token cap, a forged counter, out-of-order delivery, impersonation and a revoked key."
        }
    }
}

public struct LabConfiguration: Sendable {
    public var seed: UInt64
    public var gateway: GatewayConfiguration

    public init(seed: UInt64 = 2026_10_16, gateway: GatewayConfiguration = .standard) {
        self.seed = seed
        self.gateway = gateway
    }

    public static var standard: LabConfiguration { LabConfiguration() }
}

public struct PersonaReport: Sendable, Identifiable, Equatable {
    public let id: String
    public let kind: PersonaKind
    public var calls = 0
    public var served = 0
    public var needsVerification = 0
    public var throttled = 0
    public var blocked = 0
    public var budgetDenied = 0
    /// Budget denials keyed by scope kind ("principal", "device", "global", "other").
    public var budgetDeniedByScope: [String: Int] = [:]
    public var otherFailures = 0
    public var tokensServed = 0
    public var finalLevel: EnforcementLevel = .allow
    public var finalAssessment: RiskAssessment = .empty
    /// Score after every call, for the sparkline.
    public var riskTimeline: [Int] = []
    /// 1-based index of the first call that was not served.
    public var firstStoppedAtCall: Int?
    /// How many calls were served before the first stop.
    public var servedBeforeFirstStop: Int?

    init(id: String, kind: PersonaKind) {
        self.id = id
        self.kind = kind
    }

    public var maxRisk: Int { riskTimeline.max() ?? 0 }
}

public struct LabFinding: Sendable, Identifiable, Equatable {
    public var id: String { title }
    public let title: String
    public let detail: String
    public let passed: Bool
}

public struct LabReport: Sendable, Equatable {
    public let scenario: LabScenario
    public let personas: [PersonaReport]
    public let findings: [LabFinding]
    public let stats: GatewayStats

    public func persona(_ id: String) -> PersonaReport? { personas.first { $0.id == id } }
}

public enum GatewayLab {
    public static func run(_ scenario: LabScenario, configuration: LabConfiguration = .standard) async -> LabReport {
        switch scenario {
        case .mixedDay: return await mixedDay(configuration)
        case .accountFarm: return await accountFarm(configuration)
        case .fanOut: return await fanOut(configuration)
        case .forgery: return await forgery(configuration)
        }
    }

    // MARK: - Shared plumbing

    struct Rig {
        let clock: ManualClock
        let model: SimulatedModel
        let gateway: ShieldGateway
        let sessions: SimulatedSessions

        init(_ configuration: GatewayConfiguration, seed: UInt64, latencyMs: Millis = 0, yields: Int = 0) {
            clock = ManualClock(start: 0)
            model = SimulatedModel(clock: clock, latencyMs: latencyMs, yields: yields)
            sessions = SimulatedSessions(serverSecret: SHA256.hash(Array("lab-server-secret".utf8)).bytes)
            gateway = ShieldGateway(
                configuration: configuration, clock: clock, entropy: SeededEntropy(seed: seed),
                upstream: model, signatureVerifier: InsecureSimulatedSignature(),
                userVerifier: SimulatedUserVerification(), sessions: sessions
            )
        }

        func enroll(_ name: String) async -> SimulatedDevice {
            let secret = SHA256.hash(Array("secret:\(name)".utf8)).bytes
            let device = SimulatedDevice(keyID: DeviceKeyID("key-\(name)"), secret: secret)
            _ = await gateway.register(device.keyID, publicKey: secret)
            return device
        }

        func client(_ principal: String, device: SimulatedDevice, canVerify: Bool) -> GatewayClient {
            GatewayClient(
                principal: PrincipalID(principal), session: sessions.issue(for: PrincipalID(principal)), attester: device,
                transport: InProcessTransport(gateway: gateway),
                userVerifier: canVerify ? SimulatedUserVerification() : nil
            )
        }
    }

    struct Event {
        let at: Millis
        let persona: Int
        let payload: PromptPayload
    }

    static func record(_ result: ClientResult, into report: inout PersonaReport) {
        report.calls += 1
        var stopped = true
        switch result {
        case .completed(let output, _):
            report.served += 1
            report.tokensServed = Saturating.add(report.tokensServed, output)
            stopped = false
        case .needsUserVerification: report.needsVerification += 1
        case .retryAfter: report.throttled += 1
        case .blocked: report.blocked += 1
        case .budgetExhausted(let scope, _):
            report.budgetDenied += 1
            let key: String
            switch scope {
            case .principal?: key = "principal"
            case .device?: key = "device"
            case .global?: key = "global"
            case nil: key = "other"
            }
            report.budgetDeniedByScope[key, default: 0] += 1
        case .attestationUnavailable, .failed: report.otherFailures += 1
        }
        if stopped, report.firstStoppedAtCall == nil {
            report.firstStoppedAtCall = report.calls
            report.servedBeforeFirstStop = report.served
        }
    }

    static func finish(_ report: inout PersonaReport, gateway: ShieldGateway) async {
        let snap = await gateway.snapshot(PrincipalID(report.id))
        report.finalLevel = snap.level
        report.finalAssessment = snap.assessment
    }

    // MARK: - Prompt material

    static let topics: [String] = [
        "how do i stop my swiftui list from jumping to the top when the data source refreshes",
        "why does my core data fetch return stale objects after a background context save",
        "what is the cleanest way to cancel an async image download when a cell scrolls away",
        "how should i structure navigation state so deep links restore the right screen",
        "my app crashes with exc bad access when an observer fires after the view is gone",
        "how can i make a widget timeline refresh after the user edits data in the app",
        "what is the right way to share a model container between the app and an extension",
        "why is my scroll view stuttering when every row loads its own thumbnail",
        "how do i test a view model that awaits two network calls in parallel",
        "how do i migrate a delegate based location manager to async sequences",
        "what is a safe way to store an auth token so it survives reinstall",
        "how should i debounce search input so every keystroke does not hit the server",
    ]

    static let followUps: [String] = [
        "still failing on ios seventeen", "what about doing it with an actor",
        "can you show a shorter version", "why does that fix it", "and under swift six strict concurrency",
        "rewrite it without force unwraps", "explain the second step again", "does that leak memory",
    ]

    static let vocabulary: [String] = [
        "quantum", "ledger", "orchid", "turbine", "sonnet", "glacier", "tariff", "enzyme", "falcon",
        "mortgage", "photon", "saffron", "canyon", "protocol", "lagoon", "citadel", "vaccine", "harbor",
        "algebra", "monsoon", "verdict", "pigment", "reactor", "sparrow", "treaty", "volcano", "mosaic",
        "nebula", "osmosis", "pendulum", "quarry", "rhythm", "satire", "thermal", "umbrella", "vortex",
        "walnut", "zenith", "anchor", "bishop", "cobalt", "dynasty", "ember", "fresco", "gazette",
        "hydrogen", "isotope", "jasmine", "kernel", "lantern", "meridian", "nitrogen", "obsidian",
        "parable", "quorum", "ravine", "sextant", "tundra", "uranium", "velvet", "warden", "xenon",
    ]

    static func pick<T>(_ items: [T], _ rng: inout SeededGenerator) -> T? {
        guard !items.isEmpty else { return nil }
        return items[Int.random(in: 0..<items.count, using: &rng)]
    }

    static func randomWords(_ count: Int, _ rng: inout SeededGenerator) -> String {
        (0..<max(0, count)).compactMap { _ in pick(vocabulary, &rng) }.joined(separator: " ")
    }

    static func humanSessions(
        sessions: Int, perSession: ClosedRange<Int>, gapMs: ClosedRange<Millis>, startHours: ClosedRange<Int>,
        persona: Int, rng: inout SeededGenerator
    ) -> [Event] {
        var events: [Event] = []
        for _ in 0..<max(0, sessions) {
            var t = Saturating.add(
                Saturating.multiply(Int.random(in: startHours, using: &rng), 3_600_000),
                Int.random(in: 0..<3_600_000, using: &rng)
            )
            guard let base = pick(topics, &rng) else { continue }
            let count = Int.random(in: perSession, using: &rng)
            for i in 0..<count {
                let prompt = i == 0 ? base : base + " " + (pick(followUps, &rng) ?? "")
                events.append(Event(at: t, persona: persona, payload: PromptPayload(prompt: prompt, maxOutputTokens: 1_024)))
                t = Saturating.add(t, Int.random(in: gapMs, using: &rng))
            }
        }
        return events
    }

    static func drive(_ events: [Event], clients: [GatewayClient], reports: inout [PersonaReport], rig: Rig) async {
        let ordered = events.sorted { ($0.at, $0.persona) < ($1.at, $1.persona) }
        for event in ordered {
            guard clients.indices.contains(event.persona), reports.indices.contains(event.persona) else { continue }
            rig.clock.set(max(rig.clock.now(), event.at))
            let result = await clients[event.persona].complete(event.payload)
            record(result, into: &reports[event.persona])
            let snap = await rig.gateway.snapshot(clients[event.persona].principal)
            reports[event.persona].riskTimeline.append(snap.assessment.score)
        }
        for i in reports.indices { await finish(&reports[i], gateway: rig.gateway) }
    }

    // MARK: - Mixed day

    static func mixedDay(_ configuration: LabConfiguration) async -> LabReport {
        let rig = Rig(configuration.gateway, seed: configuration.seed)
        var rng = SeededGenerator(seed: configuration.seed)
        var reports: [PersonaReport] = []
        var clients: [GatewayClient] = []
        var events: [Event] = []

        for i in 1...6 {
            let name = "person-\(i)"
            let device = await rig.enroll(name)
            clients.append(rig.client(name, device: device, canVerify: true))
            reports.append(PersonaReport(id: name, kind: .person))
            events += humanSessions(
                sessions: 3, perSession: 4...7, gapMs: 25_000...240_000, startHours: 7...21,
                persona: clients.count - 1, rng: &rng
            )
        }

        // A curious person: one question per session, a new subject every time.
        // High novelty, human timing; novelty alone must not flag them.
        let curious = await rig.enroll("curious-person")
        clients.append(rig.client("curious-person", device: curious, canVerify: true))
        reports.append(PersonaReport(id: "curious-person", kind: .person))
        for _ in 0..<26 {
            let at = Saturating.add(
                Saturating.multiply(Int.random(in: 7...22, using: &rng), 3_600_000),
                Int.random(in: 0..<3_600_000, using: &rng)
            )
            let prompt = "what is the difference between " + randomWords(2, &rng) + " and " + randomWords(2, &rng)
            events.append(Event(at: at, persona: clients.count - 1, payload: PromptPayload(prompt: prompt, maxOutputTokens: 1_024)))
        }

        let power = await rig.enroll("power-user")
        clients.append(rig.client("power-user", device: power, canVerify: true))
        reports.append(PersonaReport(id: "power-user", kind: .powerUser))
        events += humanSessions(
            sessions: 14, perSession: 6...12, gapMs: 15_000...120_000, startHours: 6...22,
            persona: clients.count - 1, rng: &rng
        )

        // Fast sweep: one request every 20 s (+/- 0.4 s), new ground every time,
        // asks for the full 4,096 tokens, probes refusals about 8% of the time.
        let sweep = await rig.enroll("sweep-scraper")
        clients.append(rig.client("sweep-scraper", device: sweep, canVerify: false))
        reports.append(PersonaReport(id: "sweep-scraper", kind: .scraper))
        var t: Millis = 2 * 3_600_000
        for _ in 0..<120 {
            let probe = Int.random(in: 0..<100, using: &rng) < 8 ? " [restricted]" : ""
            let prompt = "explain in exhaustive detail " + randomWords(7, &rng) + probe
            events.append(Event(at: t, persona: clients.count - 1, payload: PromptPayload(prompt: prompt, maxOutputTokens: 4_096)))
            t = Saturating.add(t, 20_000 + Int.random(in: -400...400, using: &rng))
        }

        // Stealth: human-like irregular gaps, new ground every time, half the
        // requests fill a 1,500-token cap.
        let stealth = await rig.enroll("stealth-scraper")
        clients.append(rig.client("stealth-scraper", device: stealth, canVerify: false))
        reports.append(PersonaReport(id: "stealth-scraper", kind: .scraper))
        t = 9 * 3_600_000
        for _ in 0..<90 {
            let fill = Int.random(in: 0..<2, using: &rng) == 0
            let prompt = (fill ? "in exhaustive detail describe " : "briefly describe ") + randomWords(6, &rng)
            events.append(Event(at: t, persona: clients.count - 1, payload: PromptPayload(prompt: prompt, maxOutputTokens: 1_500)))
            t = Saturating.add(t, Int.random(in: 40_000...200_000, using: &rng))
        }

        await drive(events, clients: clients, reports: &reports, rig: rig)

        let humans = reports.filter { $0.kind.isHuman }
        let flaggedHumans = humans.filter { $0.blocked > 0 || $0.throttled > 0 || $0.finalLevel >= .throttle }
        let askedToVerify = humans.filter { $0.maxRisk >= configuration.gateway.enforcement.stepUpAt }
        var findings: [LabFinding] = [
            LabFinding(
                title: "No person was throttled or blocked",
                detail: "\(flaggedHumans.count) of \(humans.count) people throttled or blocked; \(askedToVerify.count) ever reached the step-up score.",
                passed: flaggedHumans.isEmpty
            ),
        ]
        if let s = reports.first(where: { $0.id == "sweep-scraper" }) {
            findings.append(LabFinding(
                title: "Sweep scraper blocked by the detector",
                detail: "Final level \(s.finalLevel), score \(s.finalAssessment.score). Served \(s.servedBeforeFirstStop ?? s.served) requests (\(s.tokensServed) tokens) before the first refusal, then \(s.calls - s.served) of \(s.calls) calls refused.",
                passed: s.finalLevel == .block
            ))
        }
        if let s = reports.first(where: { $0.id == "stealth-scraper" }) {
            findings.append(LabFinding(
                title: "Stealth scraper stopped at step-up",
                detail: "Score \(s.finalAssessment.score) (step-up at \(configuration.gateway.enforcement.stepUpAt)). With no person to pass verification, \(s.needsVerification) of \(s.calls) calls ended at the step-up demand after \(s.servedBeforeFirstStop ?? s.served) served.",
                passed: s.needsVerification > 0 && s.finalLevel >= .stepUp
            ))
        }
        return LabReport(scenario: .mixedDay, personas: reports, findings: findings, stats: await rig.gateway.stats)
    }

    // MARK: - Account farm

    static func accountFarm(_ configuration: LabConfiguration) async -> LabReport {
        let rig = Rig(configuration.gateway, seed: configuration.seed)
        var rng = SeededGenerator(seed: configuration.seed &+ 1)
        let device = await rig.enroll("farm-phone")
        var clients: [GatewayClient] = []
        var reports: [PersonaReport] = []
        var events: [Event] = []
        for i in 1...5 {
            let name = "farm-account-\(i)"
            clients.append(rig.client(name, device: device, canVerify: true))
            reports.append(PersonaReport(id: name, kind: .scraper))
            // Repetitive, human-paced, but every answer fills a 4,096 cap.
            var t = Saturating.multiply(i, 600_000)
            guard let base = pick(topics, &rng) else { continue }
            for k in 0..<24 {
                let prompt = "in exhaustive detail " + base + (k == 0 ? "" : " " + (pick(followUps, &rng) ?? ""))
                events.append(Event(at: t, persona: i - 1, payload: PromptPayload(prompt: prompt, maxOutputTokens: 4_096)))
                t = Saturating.add(t, Int.random(in: 60_000...900_000, using: &rng))
            }
        }
        await drive(events, clients: clients, reports: &reports, rig: rig)

        let limit = configuration.gateway.maxAccountsPerKey
        let refusedAccounts = reports.filter { $0.served == 0 }
        let total = reports.reduce(0) { Saturating.add($0, $1.tokensServed) }
        let deviceLimit = configuration.gateway.budget.perDevice
        // The device bucket starts full and refills continuously, so the most it
        // can ever have paid out by the end of the run is one window plus the
        // refill over the elapsed time.
        let elapsed = rig.clock.now()
        let refill = Saturating.divide(Saturating.multiply(elapsed, deviceLimit.tokens), deviceLimit.windowMs) ?? 0
        let bound = Saturating.add(deviceLimit.tokens, refill)
        let deviceStops = reports.reduce(0) { $0 + ($1.budgetDeniedByScope["device"] ?? 0) }
        let principalStops = reports.reduce(0) { $0 + ($1.budgetDeniedByScope["principal"] ?? 0) }
        let findings = [
            LabFinding(
                title: "Accounts beyond \(limit) per device never served",
                detail: "\(refusedAccounts.count) of \(reports.count) accounts were refused on every call (limit: \(limit) accounts per attested key).",
                passed: refusedAccounts.count == max(0, reports.count - limit)
            ),
            LabFinding(
                title: "The device budget, not the accounts, stopped the farm",
                detail: "\(deviceStops) calls denied at device scope, \(principalStops) at account scope. \(total) output tokens served; the device bucket could pay out at most \(bound) (\(deviceLimit.tokens) + \(refill) refilled over \(elapsed / 60_000) min), prompts included.",
                passed: deviceStops > 0 && total <= bound
            ),
        ]
        return LabReport(scenario: .accountFarm, personas: reports, findings: findings, stats: await rig.gateway.stats)
    }

    // MARK: - Parallel fan-out

    static let fanOutBudget = 5_000

    static func fanOut(_ configuration: LabConfiguration) async -> LabReport {
        var config = configuration.gateway
        config.budget.perPrincipal = .clamped(tokens: fanOutBudget, windowMs: 86_400_000)
        // The clock never moves in this scenario, so nothing refills: whatever is
        // served must fit inside the 5,000 tokens that were there at the start.
        let rig = Rig(config, seed: configuration.seed, yields: 8)
        let device = await rig.enroll("fan-out")
        let client = rig.client("fan-out-script", device: device, canVerify: true)
        var report = PersonaReport(id: "fan-out-script", kind: .scraper)
        var charged = 0
        let estimator = WordTokenEstimator()

        for wave in 0..<3 {
            let results = await withTaskGroup(of: (Int, ClientResult).self) { group -> [(Int, ClientResult)] in
                for k in 0..<20 {
                    let prompt = "summarise section \(wave * 20 + k) of the handbook"
                    group.addTask {
                        let r = await client.complete(PromptPayload(prompt: prompt, maxOutputTokens: 1_000))
                        return (estimator.estimate(prompt), r)
                    }
                }
                var all: [(Int, ClientResult)] = []
                for await r in group { all.append(r) }
                return all
            }
            for (promptTokens, result) in results {
                record(result, into: &report)
                if case .completed(let out, _) = result { charged = Saturating.add(charged, Saturating.add(promptTokens, out)) }
                report.riskTimeline.append(await rig.gateway.snapshot(client.principal).assessment.score)
            }
        }
        await finish(&report, gateway: rig.gateway)
        let stats = await rig.gateway.stats
        let limit = config.budget.maxInFlightPerPrincipal
        let findings = [
            LabFinding(
                title: "Never more than \(limit) reservations in flight",
                detail: "Peak \(stats.peakInFlightPerPrincipal) unsettled reservations for the account; \(report.throttled) calls were turned away by the in-flight limit.",
                passed: stats.peakInFlightPerPrincipal <= limit
            ),
            LabFinding(
                title: "Concurrent requests cannot overspend",
                detail: "Charged \(charged) tokens (prompt + output) against \(fanOutBudget) with no refill; \(report.budgetDenied) calls denied by budget.",
                passed: charged <= fanOutBudget
            ),
        ]
        return LabReport(scenario: .fanOut, personas: [report], findings: findings, stats: stats)
    }

    // MARK: - Replay and forgery

    static func forgery(_ configuration: LabConfiguration) async -> LabReport {
        let rig = Rig(configuration.gateway, seed: configuration.seed)
        let device = await rig.enroll("honest")
        let principal = PrincipalID("honest-user")
        let path = "/v1/complete"
        let session = rig.sessions.issue(for: principal)
        let payload = PromptPayload(prompt: "how do i debounce search input", maxOutputTokens: 512)
        var findings: [LabFinding] = []

        func signed(_ payload: PromptPayload, counter: UInt32? = nil) async -> GatewayRequest {
            let challenge = await rig.gateway.issueChallenge().bytes
            let hash = RequestBinding.clientDataHash(challenge: challenge, principal: principal, path: path, payload: payload)
            let assertion: Assertion
            if let counter {
                assertion = device.makeAssertion(counter: counter, clientDataHash: hash)
            } else if let a = await device.assert(clientDataHash: hash) {
                assertion = a
            } else {
                assertion = device.makeAssertion(counter: 0, clientDataHash: hash)
            }
            return GatewayRequest(principal: principal, session: session, path: path, payload: payload, challenge: challenge, assertion: assertion)
        }
        func check(_ title: String, _ request: GatewayRequest, expect: GatewayOutcome?) async {
            let response = await rig.gateway.handle(request)
            let passed: Bool
            if let expect { passed = response.outcome == expect } else {
                if case .served = response.outcome { passed = true } else { passed = false }
            }
            findings.append(LabFinding(title: title, detail: describe(response.outcome), passed: passed))
        }

        let honest = await signed(payload)
        await check("Honest request served", honest, expect: nil)
        await check("Verbatim replay refused", honest, expect: .rejected(.challenge(.unknownOrUsed)))

        let fresh = await rig.gateway.issueChallenge().bytes
        let rebound = GatewayRequest(principal: principal, session: session, path: path, payload: payload, challenge: fresh, assertion: honest.assertion)
        await check("Captured assertion on a new challenge refused", rebound, expect: .rejected(.assertion(.bindingMismatch)))

        let original = await signed(payload)
        let tampered = GatewayRequest(
            principal: principal, session: session, path: path, payload: PromptPayload(prompt: payload.prompt, maxOutputTokens: 4_096),
            challenge: original.challenge, assertion: original.assertion
        )
        await check("Token cap raised in transit refused", tampered, expect: .rejected(.assertion(.bindingMismatch)))

        let forgeChallenge = await rig.gateway.issueChallenge().bytes
        let forgeHash = RequestBinding.clientDataHash(challenge: forgeChallenge, principal: principal, path: path, payload: payload)
        let forged = GatewayRequest(
            principal: principal, session: session, path: path, payload: payload, challenge: forgeChallenge,
            assertion: Assertion(keyID: device.keyID, counter: .max, clientDataHash: forgeHash, signature: Array(repeating: 7, count: 32))
        )
        await check("Forged counter UInt32.max refused", forged, expect: .rejected(.assertion(.badSignature)))
        await check("Real device not locked out by the forgery", await signed(payload), expect: nil)

        // Two concurrent requests signed n+1, n+2 arrive as n+2, n+1.
        let base = device.currentCounter
        let first = await signed(payload, counter: base &+ 1)
        let second = await signed(payload, counter: base &+ 2)
        await check("Out-of-order delivery: later counter first", second, expect: nil)
        await check("Out-of-order delivery: earlier counter second", first, expect: nil)
        await check("Re-signed duplicate counter refused", await signed(payload, counter: base &+ 1), expect: .rejected(.assertion(.replayed(.duplicate))))

        let jump = await signed(payload, counter: base &+ 200)
        await check("Counter jump accepted", jump, expect: nil)
        await check("Counter 64+ behind refused", await signed(payload, counter: base &+ 100), expect: .rejected(.assertion(.replayed(.tooOld))))

        let strangerChallenge = await rig.gateway.issueChallenge().bytes
        let strangerHash = RequestBinding.clientDataHash(challenge: strangerChallenge, principal: principal, path: path, payload: payload)
        let stranger = SimulatedDevice(keyID: DeviceKeyID("never-attested"), secret: [1, 2, 3])
        let strangerRequest = GatewayRequest(
            principal: principal, session: session, path: path, payload: payload, challenge: strangerChallenge,
            assertion: stranger.makeAssertion(counter: 1, clientDataHash: strangerHash)
        )
        await check("Unattested key refused", strangerRequest, expect: .rejected(.assertion(.unknownKey)))

        // An attacker with their own attested phone and their own valid session
        // names the honest user's account. The assertion is genuine; the
        // session is not the honest user's.
        let attacker = await rig.enroll("attacker")
        let attackerSession = rig.sessions.issue(for: PrincipalID("attacker"))
        let impChallenge = await rig.gateway.issueChallenge().bytes
        let impHash = RequestBinding.clientDataHash(challenge: impChallenge, principal: principal, path: path, payload: payload)
        let impersonation = GatewayRequest(
            principal: principal, session: attackerSession, path: path, payload: payload, challenge: impChallenge,
            assertion: await attacker.assert(clientDataHash: impHash) ?? attacker.makeAssertion(counter: 1, clientDataHash: impHash)
        )
        await check("Another account's name from an attacker's phone refused", impersonation, expect: .rejected(.unauthenticated))

        await rig.gateway.revoke(device.keyID)
        await check("Revoked key refused", await signed(payload), expect: .rejected(.assertion(.revokedKey)))

        rig.clock.advance(by: configuration.gateway.challengeTTL + 1)
        let lateChallenge = await rig.gateway.issueChallenge().bytes
        rig.clock.advance(by: configuration.gateway.challengeTTL)
        let late = GatewayRequest(
            principal: principal, session: session, path: path, payload: payload, challenge: lateChallenge,
            assertion: device.makeAssertion(counter: base &+ 300, clientDataHash: RequestBinding.clientDataHash(
                challenge: lateChallenge, principal: principal, path: path, payload: payload))
        )
        await check("Expired challenge refused", late, expect: .rejected(.challenge(.expired)))

        var report = PersonaReport(id: "honest-user", kind: .person)
        await finish(&report, gateway: rig.gateway)
        let stats = await rig.gateway.stats
        report.calls = stats.received
        report.served = stats.served
        report.tokensServed = stats.tokensServed
        return LabReport(scenario: .forgery, personas: [report], findings: findings, stats: stats)
    }

    static func describe(_ outcome: GatewayOutcome) -> String {
        switch outcome {
        case .served(let tokens, _): return "served (\(tokens) tokens)"
        case .rejected(let r): return "rejected: \(r.label)"
        }
    }
}
