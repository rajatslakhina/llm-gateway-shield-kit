import XCTest
@testable import GatewayShield

final class BudgetLedgerTests: XCTestCase {
    private let p = PrincipalID("p")
    private let d = DeviceKeyID("d")

    private func policy(principal: Int = 1_000, device: Int = 5_000, global: Int = 100_000,
                        window: Millis = 1_000, inFlight: Int = 10, ttl: Millis = 10_000,
                        maxReservations: Int = 100, maxBuckets: Int = 100) -> BudgetPolicy {
        BudgetPolicy(perPrincipal: limit(principal, window), perDevice: limit(device, window), global: limit(global, window),
                     maxInFlightPerPrincipal: inFlight, reservationTTL: ttl,
                     maxOutstandingReservations: maxReservations, maxTrackedBuckets: maxBuckets)
    }

    private func reserve(_ l: inout BudgetLedger, _ tokens: Int, principal: PrincipalID? = nil, device: DeviceKeyID? = nil, at now: Millis = 0) -> Result<Reservation, BudgetDenial> {
        l.reserve(tokens: tokens, principal: principal ?? p, device: device ?? d, now: now)
    }

    func testLimitValidation() {
        XCTAssertNil(BudgetLimit(tokens: 0, windowMs: 1))
        XCTAssertNil(BudgetLimit(tokens: 1, windowMs: 0))
        XCTAssertNil(BudgetLimit(tokens: -1, windowMs: 10))
        XCTAssertNil(BudgetLimit(tokens: Int.max, windowMs: 2), "token-ms capacity would overflow")
        let c = BudgetLimit.clamped(tokens: Int.max, windowMs: Int.max)
        XCTAssertEqual(c.tokens, Int.max)
        XCTAssertEqual(c.windowMs, 1)
        XCTAssertEqual(BudgetLimit.clamped(tokens: -4, windowMs: -4).tokens, 1)
    }

    func testReserveRefundAndExactRefill() throws {
        var l = BudgetLedger(policy: policy())
        let r = try reserve(&l, 600).get()
        XCTAssertEqual(l.remaining(.principal(p), now: 0), 400)
        XCTAssertEqual(l.settle(r.id, actualTokens: 100, now: 0), .settled(refunded: 500, overage: 0))
        XCTAssertEqual(l.remaining(.principal(p), now: 0), 900)
        // 1,000 tokens per 1,000 ms refills exactly 1 token per ms.
        XCTAssertEqual(l.remaining(.principal(p), now: 37), 937)
        XCTAssertEqual(l.remaining(.principal(p), now: 5_000), 1_000, "never above capacity")
    }

    func testDenialCarriesExactRetryAfter() throws {
        var l = BudgetLedger(policy: policy())
        _ = try reserve(&l, 900).get()
        // 100 left; 250 needs 150 more at 1 token/ms.
        XCTAssertEqual(reserve(&l, 250), .failure(.insufficient(.principal(p), retryAfterMs: 150)))
        XCTAssertNoThrow(try reserve(&l, 250, at: 150).get())
    }

    func testRequestLargerThanTheWholeWindowNeverSucceeds() {
        var l = BudgetLedger(policy: policy())
        XCTAssertEqual(reserve(&l, 1_001), .failure(.exceedsLimit(.principal(p))))
        XCTAssertEqual(reserve(&l, 0), .failure(.invalidCost))
        XCTAssertEqual(reserve(&l, -5), .failure(.invalidCost))
    }

    /// All-or-nothing: when the device scope is short, the principal and global
    /// buckets must not have been debited.
    func testReservationIsAtomicAcrossScopes() throws {
        var l = BudgetLedger(policy: policy(principal: 1_000, device: 1_000))
        _ = try reserve(&l, 900, principal: PrincipalID("other")).get()   // drains the shared device
        XCTAssertEqual(reserve(&l, 500), .failure(.insufficient(.device(d), retryAfterMs: 400)))
        XCTAssertEqual(l.remaining(.principal(p), now: 0), 1_000)
        XCTAssertEqual(l.remaining(.global, now: 0), 99_100)
    }

    func testOverageGoesIntoBoundedDebt() throws {
        var l = BudgetLedger(policy: policy())
        let r = try reserve(&l, 100).get()
        XCTAssertEqual(l.settle(r.id, actualTokens: Int.max, now: 0), .settled(refunded: 0, overage: Int.max - 100))
        XCTAssertEqual(l.remaining(.principal(p), now: 0), 0)
        // Debt is floored at minus one full window, so it takes exactly one window
        // to climb back to zero and a second to refill.
        XCTAssertEqual(l.remaining(.principal(p), now: 1_000), 0)
        XCTAssertEqual(l.remaining(.principal(p), now: 1_500), 500)
        XCTAssertEqual(l.remaining(.principal(p), now: 2_000), 1_000)
    }

    func testSettleIsIdempotentAndNegativeActualIsClamped() throws {
        var l = BudgetLedger(policy: policy())
        let r = try reserve(&l, 300).get()
        XCTAssertEqual(l.settle(r.id, actualTokens: -50, now: 0), .settled(refunded: 300, overage: 0))
        XCTAssertEqual(l.settle(r.id, actualTokens: 0, now: 0), .unknown)
        XCTAssertEqual(l.settle(9_999, actualTokens: 0, now: 0), .unknown)
        XCTAssertEqual(l.remaining(.principal(p), now: 0), 1_000)
    }

    func testInFlightLimitAndRelease() throws {
        var l = BudgetLedger(policy: policy(inFlight: 2))
        let a = try reserve(&l, 10).get()
        _ = try reserve(&l, 10).get()
        XCTAssertEqual(reserve(&l, 10), .failure(.tooManyInFlight(limit: 2)))
        XCTAssertNoThrow(try reserve(&l, 10, principal: PrincipalID("q")).get(), "the limit is per principal")
        _ = l.settle(a.id, actualTokens: 10, now: 0)
        XCTAssertEqual(l.inFlight(for: p), 1)
        XCTAssertNoThrow(try reserve(&l, 10).get())
    }

    func testUnsettledReservationIsChargedAtTTL() throws {
        var l = BudgetLedger(policy: policy(inFlight: 1, ttl: 100))
        let r = try reserve(&l, 400).get()
        l.sweepExpired(now: 100)
        XCTAssertEqual(l.expiredCharged, 1)
        XCTAssertEqual(l.inFlight(for: p), 0, "the slot is released")
        XCTAssertEqual(l.settle(r.id, actualTokens: 0, now: 101), .expiredAlreadyCharged, "a late settle refunds nothing")
        XCTAssertEqual(l.remaining(.principal(p), now: 100), 700, "400 charged, 100 refilled")
    }

    func testOutstandingReservationsAreBounded() throws {
        var l = BudgetLedger(policy: policy(inFlight: 100, maxReservations: 2))
        _ = try reserve(&l, 1).get()
        _ = try reserve(&l, 1).get()
        XCTAssertEqual(reserve(&l, 1), .failure(.ledgerFull))
    }

    func testBucketMemoryIsBoundedByPruningOnlyFullIdleBuckets() throws {
        var l = BudgetLedger(policy: policy(maxBuckets: 5))
        // global + principal + device = 3 buckets.
        let r = try reserve(&l, 10, principal: PrincipalID("a"), device: DeviceKeyID("da")).get()
        _ = l.settle(r.id, actualTokens: 10, now: 0)
        // A second pair needs 2 more: 5 total, allowed.
        _ = try reserve(&l, 10, principal: PrincipalID("b"), device: DeviceKeyID("db")).get()
        XCTAssertEqual(l.trackedBuckets, 5)
        // A third pair at t=0: nothing is full yet (both spent 10) -> refuse rather than grow.
        XCTAssertEqual(reserve(&l, 10, principal: PrincipalID("c"), device: DeviceKeyID("dc")), .failure(.ledgerFull))
        // Later, "a" has refilled and is idle, so it can be dropped; "b" is still in flight.
        XCTAssertNoThrow(try reserve(&l, 10, principal: PrincipalID("c"), device: DeviceKeyID("dc"), at: 1_000).get())
        XCTAssertLessThanOrEqual(l.trackedBuckets, 5)
    }

    func testClockStepBackwardsNeverRefills() throws {
        var l = BudgetLedger(policy: policy())
        _ = try reserve(&l, 500, at: 1_000).get()
        XCTAssertEqual(l.remaining(.principal(p), now: 0), 500)
        _ = try reserve(&l, 100, at: 0).get()
        XCTAssertEqual(l.remaining(.principal(p), now: 1_000), 400, "time spent 'before' the last update is not credited")
    }
}
