/// A token budget: `tokens` per rolling `windowMs`, refilled continuously.
public struct BudgetLimit: Hashable, Sendable {
    public let tokens: Int
    public let windowMs: Millis

    /// `nil` unless both values are positive and `tokens * windowMs` fits in `Int`
    /// (the ledger keeps balances in token-milliseconds; see `BudgetLedger`).
    public init?(tokens: Int, windowMs: Millis) {
        guard tokens > 0, windowMs > 0 else { return nil }
        guard !tokens.multipliedReportingOverflow(by: windowMs).overflow else { return nil }
        self.tokens = tokens
        self.windowMs = windowMs
    }

    /// Total version for trusted constants: clamps instead of failing, so the
    /// product always fits (`windowMs` is capped at `Int.max / tokens`).
    public static func clamped(tokens: Int, windowMs: Millis) -> BudgetLimit {
        let t = max(1, tokens)
        let w = Saturating.clamp(windowMs, 1, Int.max / t)   // t >= 1: no division by zero
        return BudgetLimit(trusted: t, windowMs: w)
    }

    private init(trusted tokens: Int, windowMs: Millis) {
        self.tokens = tokens
        self.windowMs = windowMs
    }

    /// Capacity in token-milliseconds. Cannot overflow: checked in `init`.
    var capacityUnits: Int { tokens * windowMs }
}

public enum BudgetScope: Hashable, Sendable, CustomStringConvertible {
    case principal(PrincipalID)
    case device(DeviceKeyID)
    case global

    public var description: String {
        switch self {
        case .principal(let p): return "principal \(p)"
        case .device(let d): return "device \(d)"
        case .global: return "global"
        }
    }
}

public struct BudgetPolicy: Sendable {
    public var perPrincipal: BudgetLimit
    public var perDevice: BudgetLimit
    public var global: BudgetLimit
    /// Concurrent unsettled requests one principal may hold. This is what stops a
    /// script fanning out 500 parallel requests before any of them settles.
    public var maxInFlightPerPrincipal: Int
    /// A reservation not settled by then is charged in full (fail closed).
    public var reservationTTL: Millis
    public var maxOutstandingReservations: Int
    /// Upper bound on per-principal and per-device buckets kept in memory.
    public var maxTrackedBuckets: Int

    public init(
        perPrincipal: BudgetLimit,
        perDevice: BudgetLimit,
        global: BudgetLimit,
        maxInFlightPerPrincipal: Int,
        reservationTTL: Millis,
        maxOutstandingReservations: Int,
        maxTrackedBuckets: Int
    ) {
        self.perPrincipal = perPrincipal
        self.perDevice = perDevice
        self.global = global
        self.maxInFlightPerPrincipal = max(1, maxInFlightPerPrincipal)
        self.reservationTTL = max(1, reservationTTL)
        self.maxOutstandingReservations = max(1, maxOutstandingReservations)
        self.maxTrackedBuckets = max(2, maxTrackedBuckets)
    }
}

public enum BudgetDenial: Error, Equatable, Sendable {
    case invalidCost
    /// The request alone is larger than the scope's whole window: it can never
    /// succeed, so it gets no retry time.
    case exceedsLimit(BudgetScope)
    case insufficient(BudgetScope, retryAfterMs: Millis)
    case tooManyInFlight(limit: Int)
    /// Bookkeeping is at its memory bound. Fail closed rather than grow.
    case ledgerFull
}

public struct Reservation: Hashable, Sendable {
    public let id: UInt64
    public let principal: PrincipalID
    public let device: DeviceKeyID
    public let tokens: Int
    public let expiresAt: Millis
}

public enum SettleOutcome: Equatable, Sendable {
    case settled(refunded: Int, overage: Int)
    /// The TTL sweep already charged it in full; nothing changes.
    case expiredAlreadyCharged
    case unknown
}

/// Reserve-then-settle token budgets across three scopes.
///
/// Why reserve: a check-then-charge budget lets ten concurrent requests all pass
/// the check before any of them is charged. Reserving `prompt + maxOutput` up
/// front and refunding the unused part at settle time means the sum of what is
/// in flight can never exceed what is left.
///
/// Why token-milliseconds: a bucket of `T` tokens per `W` ms refills at exactly
/// `T` units per ms when balances are kept in `token * ms`, so refill is integer
/// and exact, with no rounding drift and no floating point.
///
/// Reservations are all-or-nothing across scopes: either every scope is debited
/// or none is.
public struct BudgetLedger: Sendable {
    struct Bucket: Sendable {
        var level: Int
        var updatedAt: Millis

        mutating func refill(to now: Millis, limit: BudgetLimit) {
            let elapsed = max(0, Saturating.subtract(now, updatedAt))
            let added = Saturating.multiply(elapsed, limit.tokens)
            level = min(limit.capacityUnits, Saturating.add(level, added))
            updatedAt = max(updatedAt, now)   // a clock step backwards never refills
        }
    }

    public let policy: BudgetPolicy
    private var buckets: [BudgetScope: Bucket] = [:]
    private var reservations: [UInt64: Reservation] = [:]
    private var inFlight: [PrincipalID: Int] = [:]
    private var recentlyExpired: Set<UInt64> = []
    private var recentlyExpiredOrder: [UInt64] = []
    private var nextID: UInt64 = 1
    /// Earliest `expiresAt` among outstanding reservations, so the per-request
    /// sweep is O(1) unless something is actually due.
    private var earliestExpiry: Millis = Int.max
    public private(set) var expiredCharged = 0

    public init(policy: BudgetPolicy) { self.policy = policy }

    public var outstandingReservations: Int { reservations.count }
    public var trackedBuckets: Int { buckets.count }
    public func inFlight(for principal: PrincipalID) -> Int { inFlight[principal] ?? 0 }

    public func limit(for scope: BudgetScope) -> BudgetLimit {
        switch scope {
        case .principal: return policy.perPrincipal
        case .device: return policy.perDevice
        case .global: return policy.global
        }
    }

    /// Whole tokens currently available in `scope` (0 when in debt).
    public func remaining(_ scope: BudgetScope, now: Millis) -> Int {
        let limit = limit(for: scope)
        var bucket = buckets[scope] ?? Bucket(level: limit.capacityUnits, updatedAt: now)
        bucket.refill(to: now, limit: limit)
        return max(0, Saturating.divide(bucket.level, limit.windowMs) ?? 0)
    }

    public mutating func reserve(
        tokens: Int,
        principal: PrincipalID,
        device: DeviceKeyID,
        now: Millis
    ) -> Result<Reservation, BudgetDenial> {
        guard tokens > 0 else { return .failure(.invalidCost) }
        sweepExpired(now: now)

        let held = inFlight[principal] ?? 0
        guard held < policy.maxInFlightPerPrincipal else {
            return .failure(.tooManyInFlight(limit: policy.maxInFlightPerPrincipal))
        }
        guard reservations.count < policy.maxOutstandingReservations else { return .failure(.ledgerFull) }

        let scopes: [BudgetScope] = [.principal(principal), .device(device), .global]
        let newScopes = scopes.filter { buckets[$0] == nil }.count
        if buckets.count + newScopes > policy.maxTrackedBuckets {
            pruneFullBuckets(now: now)
            guard buckets.count + newScopes <= policy.maxTrackedBuckets else { return .failure(.ledgerFull) }
        }

        // Phase 1: check every scope without mutating anything.
        var refilled: [BudgetScope: Bucket] = [:]
        var worstRetry: Millis = 0
        var shortScope: BudgetScope?
        for scope in scopes {
            let limit = limit(for: scope)
            guard tokens <= limit.tokens else { return .failure(.exceedsLimit(scope)) }
            var bucket = buckets[scope] ?? Bucket(level: limit.capacityUnits, updatedAt: now)
            bucket.refill(to: now, limit: limit)
            refilled[scope] = bucket
            // tokens <= limit.tokens, so this cannot overflow (capacity was checked).
            let needed = tokens * limit.windowMs
            if bucket.level < needed {
                let deficit = Saturating.subtract(needed, bucket.level)
                let wait = Saturating.ceilDivide(deficit, limit.tokens) ?? Int.max
                if wait >= worstRetry { worstRetry = wait; shortScope = scope }
            }
        }
        if let scope = shortScope { return .failure(.insufficient(scope, retryAfterMs: worstRetry)) }

        // Phase 2: every scope passed; debit them all.
        for scope in scopes {
            guard var bucket = refilled[scope] else { continue }   // always present
            bucket.level = Saturating.subtract(bucket.level, tokens * limit(for: scope).windowMs)
            buckets[scope] = bucket
        }
        let id = nextID
        nextID &+= 1   // 2^64 reservations will not happen; wrap rather than trap
        let reservation = Reservation(
            id: id, principal: principal, device: device, tokens: tokens,
            expiresAt: Saturating.add(now, policy.reservationTTL)
        )
        reservations[id] = reservation
        earliestExpiry = min(earliestExpiry, reservation.expiresAt)
        inFlight[principal] = held + 1
        return .success(reservation)
    }

    /// Settles a reservation with what was actually used.
    ///
    /// Used less: the difference is refunded. Used more (a tokenizer disagreed
    /// with the estimate): the extra is charged, and the bucket may go into debt,
    /// floored at minus one full window.
    public mutating func settle(_ id: UInt64, actualTokens: Int, now: Millis) -> SettleOutcome {
        guard let reservation = reservations.removeValue(forKey: id) else {
            return recentlyExpired.contains(id) ? .expiredAlreadyCharged : .unknown
        }
        releaseInFlight(reservation.principal)
        let actual = max(0, actualTokens)
        let refund = max(0, reservation.tokens - actual)        // both non-negative: no overflow
        let overage = max(0, Saturating.subtract(actual, reservation.tokens))
        for scope in [BudgetScope.principal(reservation.principal), .device(reservation.device), .global] {
            let limit = limit(for: scope)
            var bucket = buckets[scope] ?? Bucket(level: limit.capacityUnits, updatedAt: now)
            bucket.refill(to: now, limit: limit)
            if refund > 0 {
                let credit = Saturating.multiply(refund, limit.windowMs)
                bucket.level = min(limit.capacityUnits, Saturating.add(bucket.level, credit))
            }
            if overage > 0 {
                let debit = Saturating.multiply(overage, limit.windowMs)
                bucket.level = max(-limit.capacityUnits, Saturating.subtract(bucket.level, debit))
            }
            buckets[scope] = bucket
        }
        return .settled(refunded: refund, overage: overage)
    }

    /// Charges every reservation past its TTL in full. Its tokens were debited at
    /// reserve time, so "charge" means "never refund".
    public mutating func sweepExpired(now: Millis) {
        guard now >= earliestExpiry else { return }
        defer { earliestExpiry = reservations.values.map(\.expiresAt).min() ?? Int.max }
        let expired = reservations.values.filter { $0.expiresAt <= now }
        for reservation in expired {
            reservations[reservation.id] = nil
            releaseInFlight(reservation.principal)
            expiredCharged += 1
            rememberExpired(reservation.id)
        }
    }

    private mutating func releaseInFlight(_ principal: PrincipalID) {
        let n = (inFlight[principal] ?? 0) - 1
        inFlight[principal] = n > 0 ? n : nil
    }

    private mutating func rememberExpired(_ id: UInt64) {
        recentlyExpired.insert(id)
        recentlyExpiredOrder.append(id)
        if recentlyExpiredOrder.count > 1024 {
            let drop = recentlyExpiredOrder.removeFirst()
            recentlyExpired.remove(drop)
        }
    }

    /// A full bucket with nothing in flight is indistinguishable from an absent
    /// one, so dropping it loses no information.
    private mutating func pruneFullBuckets(now: Millis) {
        let busyPrincipals = Set(reservations.values.map(\.principal))
        let busyDevices = Set(reservations.values.map(\.device))
        for (scope, var bucket) in buckets {
            switch scope {
            case .global: continue
            case .principal(let p) where busyPrincipals.contains(p): continue
            case .device(let d) where busyDevices.contains(d): continue
            default: break
            }
            let limit = limit(for: scope)
            bucket.refill(to: now, limit: limit)
            if bucket.level >= limit.capacityUnits { buckets[scope] = nil }
        }
    }
}
