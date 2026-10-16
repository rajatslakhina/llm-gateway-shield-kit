#if canImport(SwiftUI)
import SwiftUI
import Observation
import GatewayShield

/// Drives one lab run at a time. A newer run always wins: a slow earlier run
/// that finishes late is discarded instead of overwriting the newer report.
@MainActor
@Observable
public final class ShieldLabModel {
    public var scenario: LabScenario
    public private(set) var report: LabReport?
    public private(set) var isRunning = false
    public var selectedPersonaID: String?
    public let configuration: LabConfiguration
    /// Seed of the report on screen. Switching scenario uses the configured seed
    /// (so the numbers match the library README); "Run again" moves to the next
    /// seed so the scenario replays with different simulated traffic.
    public private(set) var lastSeed: UInt64
    private var generation = 0
    private var runs: UInt64 = 0

    public init(configuration: LabConfiguration, scenario: LabScenario = .mixedDay) {
        self.configuration = configuration
        self.scenario = scenario
        self.lastSeed = configuration.seed
    }

    public func run(reseed: Bool = false) async {
        generation += 1
        let mine = generation
        isRunning = true
        runs = reseed ? runs &+ 1 : 0              // wrapping is fine for a seed offset
        var config = configuration
        config.seed = configuration.seed &+ runs
        let result = await GatewayLab.run(scenario, configuration: config)
        guard mine == generation else { return }
        report = result
        lastSeed = config.seed
        isRunning = false
        // Keep the user's row if it still exists; otherwise show the highest-risk persona.
        if selectedPersonaID.flatMap({ result.persona($0) }) == nil {
            selectedPersonaID = result.personas.max { $0.maxRisk < $1.maxRisk }?.id
        }
    }

    public var selectedPersona: PersonaReport? {
        guard let id = selectedPersonaID else { return nil }
        return report?.persona(id)
    }
}

/// The demo's root screen: pick a scenario, watch a real `ShieldGateway` decide.
public struct ShieldLabView: View {
    @State private var model: ShieldLabModel

    public init(configuration: LabConfiguration) {
        _model = State(initialValue: ShieldLabModel(configuration: configuration))
    }

    public var body: some View {
        NavigationStack {
            List {
                Section {
                    Picker("Scenario", selection: $model.scenario) {
                        ForEach(LabScenario.allCases) { Text($0.shortTitle).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    Text(model.scenario.summary)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    if model.isRunning {
                        HStack(spacing: 8) {
                            ProgressView()
                            Text("Running…").font(.footnote).foregroundStyle(.secondary)
                        }
                    } else if model.report?.scenario == model.scenario {
                        Text("Seed \(model.lastSeed) · tap ↻ to replay with new traffic")
                            .font(.caption2.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                }

                if let report = model.report, report.scenario == model.scenario {
                    FindingsSection(findings: report.findings)
                    PersonasSection(report: report, selection: $model.selectedPersonaID)
                    if let persona = model.selectedPersona {
                        RiskBreakdownSection(persona: persona, policy: model.configuration.gateway.enforcement)
                    }
                    StatsSection(stats: report.stats)
                } else {
                    Section {
                        HStack(spacing: 12) {
                            ProgressView()
                            Text("Running \(model.scenario.rawValue)…").foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .navigationTitle("Gateway Shield")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        Task { await model.run(reseed: true) }
                    } label: {
                        Label("Run again", systemImage: "arrow.clockwise")
                    }
                    .disabled(model.isRunning)
                }
            }
            .task(id: model.scenario) { await model.run() }
        }
    }
}

extension LabScenario {
    var shortTitle: String {
        switch self {
        case .mixedDay: return "Day"
        case .accountFarm: return "Farm"
        case .fanOut: return "Fan-out"
        case .forgery: return "Forgery"
        }
    }
}

extension EnforcementLevel {
    var tint: Color {
        switch self {
        case .allow: return .green
        case .stepUp: return .yellow
        case .throttle: return .orange
        case .block: return .red
        }
    }
}

struct FindingsSection: View {
    let findings: [LabFinding]

    var body: some View {
        Section("What the gateway did") {
            if findings.isEmpty {
                Text("No findings for this run.").foregroundStyle(.secondary)
            }
            ForEach(findings) { finding in
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    Image(systemName: finding.passed ? "checkmark.seal.fill" : "xmark.octagon.fill")
                        .foregroundStyle(finding.passed ? .green : .red)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(finding.title).font(.subheadline.weight(.semibold))
                        Text(finding.detail).font(.caption).foregroundStyle(.secondary)
                    }
                }
                .accessibilityElement(children: .combine)
            }
        }
    }
}

struct PersonasSection: View {
    let report: LabReport
    @Binding var selection: String?

    var body: some View {
        Section("Traffic (tap a row)") {
            if report.personas.isEmpty {
                Text("No traffic in this scenario.").foregroundStyle(.secondary)
            }
            ForEach(report.personas) { persona in
                Button {
                    selection = persona.id
                } label: {
                    PersonaRow(persona: persona, selected: persona.id == selection)
                }
                .buttonStyle(.plain)
            }
        }
    }
}

struct PersonaRow: View {
    let persona: PersonaReport
    let selected: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(persona.id).font(.subheadline.weight(selected ? .bold : .regular))
                Text(persona.kind.rawValue).font(.caption2).foregroundStyle(.secondary)
                Spacer()
                Text(persona.finalLevel.description)
                    .font(.caption.weight(.semibold))
                    .padding(.horizontal, 8).padding(.vertical, 2)
                    .background(persona.finalLevel.tint.opacity(0.2), in: Capsule())
            }
            HStack(spacing: 12) {
                Label("\(persona.served)/\(persona.calls)", systemImage: "checkmark.circle")
                Label("\(persona.tokensServed)", systemImage: "text.word.spacing")
                if persona.needsVerification > 0 { Label("\(persona.needsVerification)", systemImage: "faceid") }
                if persona.blocked > 0 { Label("\(persona.blocked)", systemImage: "hand.raised") }
                if persona.budgetDenied > 0 { Label("\(persona.budgetDenied)", systemImage: "gauge.with.dots.needle.100percent") }
                if persona.throttled > 0 { Label("\(persona.throttled)", systemImage: "tortoise") }
            }
            .font(.caption2)
            .foregroundStyle(.secondary)
            Sparkline(values: persona.riskTimeline, tint: persona.finalLevel.tint)
                .frame(height: 22)
        }
        .padding(.vertical, 2)
        .contentShape(Rectangle())
    }
}

/// Risk score (0...100) after each call.
struct Sparkline: View {
    let values: [Int]
    let tint: Color

    var body: some View {
        Canvas { context, size in
            guard values.count >= 2 else { return }
            var path = Path()
            let step = size.width / CGFloat(values.count - 1)   // count >= 2: non-zero divisor
            for (i, v) in values.enumerated() {
                let y = size.height * (1 - CGFloat(min(max(v, 0), 100)) / 100)
                let point = CGPoint(x: CGFloat(i) * step, y: y)
                if i == 0 { path.move(to: point) } else { path.addLine(to: point) }
            }
            context.stroke(path, with: .color(tint), lineWidth: 1.5)
        }
        .accessibilityLabel("Risk score over time, peak \(values.max() ?? 0)")
    }
}

struct RiskBreakdownSection: View {
    let persona: PersonaReport
    let policy: EnforcementPolicy

    var body: some View {
        Section("Why \(persona.id) scored \(persona.finalAssessment.score)") {
            if persona.finalAssessment.contributions.isEmpty {
                Text("Fewer than the minimum samples: score held at 0 (cold start).")
                    .font(.caption).foregroundStyle(.secondary)
            }
            ForEach(Feature.allCases, id: \.self) { feature in
                let points = persona.finalAssessment.contributions[feature] ?? 0
                HStack {
                    Text(feature.title).font(.caption).frame(width: 110, alignment: .leading)
                    GeometryReader { geo in
                        Capsule().fill(.quaternary)
                            .overlay(alignment: .leading) {
                                Capsule().fill(Color.accentColor)
                                    .frame(width: geo.size.width * CGFloat(min(max(points, 0), 30)) / 30)
                            }
                    }
                    .frame(height: 8)
                    Text("\(points)").font(.caption.monospacedDigit()).frame(width: 28, alignment: .trailing)
                }
            }
            Text("Step-up at \(policy.stepUpAt), throttle at \(policy.throttleAt), block at \(policy.blockAt). Each bar is that feature's share of the score.")
                .font(.caption2).foregroundStyle(.secondary)
        }
    }
}

extension Feature {
    var title: String {
        switch self {
        case .novelty: return "Novelty"
        case .cadence: return "Machine cadence"
        case .lengthSaturation: return "Length saturation"
        case .refusalProbing: return "Refusal probing"
        case .volume: return "Volume"
        }
    }
}

struct StatsSection: View {
    let stats: GatewayStats

    var body: some View {
        Section("Gateway counters") {
            LabeledContent("Requests received", value: "\(stats.received)")
            LabeledContent("Served", value: "\(stats.served)")
            LabeledContent("Output tokens served", value: "\(stats.tokensServed)")
            ForEach(stats.rejections.sorted { $0.key < $1.key }, id: \.key) { entry in
                LabeledContent("Rejected: \(entry.key)", value: "\(entry.value)")
            }
        }
    }
}

#endif
