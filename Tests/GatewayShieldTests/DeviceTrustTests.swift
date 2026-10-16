import XCTest
@testable import GatewayShield

final class ChallengeStoreTests: XCTestCase {
    func testSingleUseAndExpiry() {
        var store = ChallengeStore(ttl: 1_000, capacity: 10)
        _ = store.insert([1], now: 0)
        XCTAssertEqual(store.consume([1], now: 999), .fresh)
        XCTAssertEqual(store.consume([1], now: 999), .unknownOrUsed, "second use refused")
        _ = store.insert([2], now: 0)
        XCTAssertEqual(store.consume([2], now: 1_000), .expired, "expiry is exclusive at ttl")
        XCTAssertEqual(store.consume([2], now: 1_000), .unknownOrUsed, "an expired challenge is consumed too")
        XCTAssertEqual(store.consume([9], now: 0), .unknownOrUsed)
    }

    func testCapacityEvictsOldestAndBoundsMemory() {
        var store = ChallengeStore(ttl: 1_000_000, capacity: 3)
        for i in 0..<100 { _ = store.insert([UInt8(i)], now: i) }
        XCTAssertEqual(store.outstandingCount, 3)
        XCTAssertEqual(store.evictedUnused, 97)
        XCTAssertEqual(store.consume([0], now: 200), .unknownOrUsed, "oldest was evicted")
        XCTAssertEqual(store.consume([99], now: 200), .fresh, "newest survives")
    }

    /// One abandoned challenge at the front of the queue must not let consumed
    /// entries pile up behind it.
    func testIssueOrderQueueStaysBoundedBehindAnAbandonedChallenge() {
        var store = ChallengeStore(ttl: 1_000_000, capacity: 3)
        _ = store.insert([0xff, 0xff, 0xff, 0xff, 0xff], now: 0)   // never consumed
        for i in 0..<200_000 {
            let bytes = withUnsafeBytes(of: UInt32(i).bigEndian, Array.init)
            _ = store.insert(bytes, now: 1)
            XCTAssertEqual(store.consume(bytes, now: 1), .fresh)
        }
        XCTAssertEqual(store.outstandingCount, 1)
        XCTAssertLessThanOrEqual(store.orderStorageCount, 65)
        XCTAssertEqual(store.consume([0xff, 0xff, 0xff, 0xff, 0xff], now: 2), .fresh, "the live entry survives compaction")
    }

    func testExpiredEntriesArePrunedWithoutCountingAsEvictions() {
        var store = ChallengeStore(ttl: 10, capacity: 5)
        for i in 0..<5 { _ = store.insert([UInt8(i)], now: 0) }
        _ = store.insert([200], now: 50)
        XCTAssertEqual(store.outstandingCount, 1)
        XCTAssertEqual(store.evictedUnused, 0)
    }

    func testDegenerateConfigurationIsClamped() {
        let store = ChallengeStore(ttl: -5, capacity: 0)
        XCTAssertEqual(store.ttl, 1)
        XCTAssertEqual(store.capacity, 1)
    }
}

final class ReplayWindowTests: XCTestCase {
    func testAttestationCounterIsAlreadyUsed() {
        var w = ReplayWindow()
        XCTAssertEqual(w.check(0), .duplicate)
        XCTAssertTrue(w.record(1))
        XCTAssertEqual(w.check(1), .duplicate)
    }

    func testOutOfOrderWithinWindowAcceptedOnceEach() {
        var w = ReplayWindow()
        XCTAssertTrue(w.record(5))
        XCTAssertTrue(w.record(3), "3 arrives after 5: still inside the window")
        XCTAssertTrue(w.record(4))
        XCTAssertFalse(w.record(3), "but only once")
        XCTAssertEqual(w.check(4), .duplicate)
        XCTAssertEqual(w.highest, 5)
    }

    func testWindowEdgeIsExact() {
        var w = ReplayWindow()
        XCTAssertTrue(w.record(100))
        XCTAssertEqual(w.check(100 - 63), .fresh, "distance 63 is the oldest slot")
        XCTAssertEqual(w.check(100 - 64), .tooOld, "distance 64 is outside")
    }

    func testLargeJumpClearsHistory() {
        var w = ReplayWindow()
        XCTAssertTrue(w.record(10))
        XCTAssertTrue(w.record(10 + 64))
        XCTAssertEqual(w.check(10), .tooOld)
        XCTAssertEqual(w.check(11), .fresh, "11 was never seen and is distance 63")
        XCTAssertTrue(w.record(500))
        XCTAssertEqual(w.check(500 - 1), .fresh)
    }

    func testCounterCeilingDoesNotTrap() {
        var w = ReplayWindow()
        XCTAssertTrue(w.record(UInt32.max))
        XCTAssertEqual(w.check(UInt32.max), .duplicate)
        XCTAssertEqual(w.check(UInt32.max - 1), .fresh)
        XCTAssertEqual(w.check(0), .tooOld)
    }

    /// Why a window and not App Attest's "greater than the last counter" rule:
    /// the strict rule rejects a legitimate request that was signed first but
    /// arrived second. The window accepts it and still refuses its duplicate.
    func testStrictCounterRuleWouldRejectLegitimateReordering() {
        var strictLast: UInt32 = 0
        func strictAccept(_ c: UInt32) -> Bool { guard c > strictLast else { return false }; strictLast = c; return true }
        var window = ReplayWindow()
        let arrivals: [UInt32] = [2, 1]      // signed 1 then 2, delivered 2 then 1
        XCTAssertEqual(arrivals.map(strictAccept), [true, false])
        XCTAssertEqual(arrivals.map { window.record($0) }, [true, true])
        XCTAssertFalse(window.record(1))
    }
}

final class KeyRegistryTests: XCTestCase {
    private let verifier = InsecureSimulatedSignature()
    private let secret: [UInt8] = [9, 9, 9]

    private func assertion(_ counter: UInt32, hash: SHA256Digest, secret: [UInt8]? = nil) -> Assertion {
        let msg = Assertion.signedMessage(counter: counter, clientDataHash: hash)
        return Assertion(keyID: DeviceKeyID("k"), counter: counter, clientDataHash: hash,
                         signature: InsecureSimulatedSignature.sign(msg, secret: secret ?? self.secret))
    }

    private func registry(accounts: Int = 3) -> KeyRegistry {
        var r = KeyRegistry(maxAccountsPerKey: accounts, maxKeys: 10)
        XCTAssertEqual(r.register(DeviceKeyID("k"), publicKey: secret), .registered)
        return r
    }

    func testRegistrationRules() {
        var r = KeyRegistry(maxAccountsPerKey: 1, maxKeys: 1)
        XCTAssertEqual(r.register(DeviceKeyID("a"), publicKey: [1]), .registered)
        XCTAssertEqual(r.register(DeviceKeyID("a"), publicKey: [2]), .alreadyRegistered)
        XCTAssertEqual(r.register(DeviceKeyID("b"), publicKey: [1]), .registryFull)
    }

    func testChecksInOrder() {
        var r = registry()
        let h = SHA256.hash([1])
        let p = PrincipalID("p")
        XCTAssertEqual(r.verify(assertion(1, hash: h), expectedClientDataHash: SHA256.hash([2]), principal: p, verifier: verifier), .bindingMismatch)
        XCTAssertEqual(r.verify(assertion(1, hash: h, secret: [0]), expectedClientDataHash: h, principal: p, verifier: verifier), .badSignature)
        XCTAssertEqual(r.verify(assertion(1, hash: h), expectedClientDataHash: h, principal: p, verifier: verifier), .accepted)
        XCTAssertEqual(r.verify(assertion(1, hash: h), expectedClientDataHash: h, principal: p, verifier: verifier), .replayed(.duplicate))
        let unknown = Assertion(keyID: DeviceKeyID("zz"), counter: 2, clientDataHash: h, signature: [])
        XCTAssertEqual(r.verify(unknown, expectedClientDataHash: h, principal: p, verifier: verifier), .unknownKey)
        r.revoke(DeviceKeyID("k"))
        XCTAssertEqual(r.verify(assertion(2, hash: h), expectedClientDataHash: h, principal: p, verifier: verifier), .revokedKey)
    }

    /// The counter is recorded only after the signature verifies. If it were
    /// recorded first, this unsigned UInt32.max assertion would lock the real
    /// device out for good.
    func testForgedHighCounterDoesNotLockOutTheRealDevice() {
        var r = registry()
        let h = SHA256.hash([1])
        let forged = Assertion(keyID: DeviceKeyID("k"), counter: .max, clientDataHash: h, signature: [0xde, 0xad])
        XCTAssertEqual(r.verify(forged, expectedClientDataHash: h, principal: PrincipalID("p"), verifier: verifier), .badSignature)
        XCTAssertEqual(r.records[DeviceKeyID("k")]?.window.highest, 0)
        XCTAssertEqual(r.verify(assertion(1, hash: h), expectedClientDataHash: h, principal: PrincipalID("p"), verifier: verifier), .accepted)
    }

    /// Account slots are claimed only by a verified assertion. Key ids travel in
    /// every request, so if binding came first an unsigned assertion could use
    /// up a victim install's account slots.
    func testUnsignedAssertionCannotClaimAnAccountSlot() {
        var r = registry(accounts: 1)
        let h = SHA256.hash([1])
        let unsigned = assertion(1, hash: h, secret: [0])
        XCTAssertEqual(r.verify(unsigned, expectedClientDataHash: h, principal: PrincipalID("intruder"), verifier: verifier), .badSignature)
        XCTAssertEqual(r.records[DeviceKeyID("k")]?.accounts, [])
        XCTAssertEqual(r.verify(assertion(1, hash: h), expectedClientDataHash: h, principal: PrincipalID("owner"), verifier: verifier), .accepted)
    }

    /// Control for the test above it in spirit: the signature check is load-bearing: with a verifier that accepts
    /// anything, the same forgery goes through.
    func testForgeryPassesWithABrokenVerifier() {
        var r = registry()
        let h = SHA256.hash([1])
        let forged = Assertion(keyID: DeviceKeyID("k"), counter: 7, clientDataHash: h, signature: [0])
        XCTAssertEqual(r.verify(forged, expectedClientDataHash: h, principal: PrincipalID("p"), verifier: AcceptAnySignature()), .accepted)
    }

    func testAccountLimitPerKeyAndRejectionDoesNotConsumeTheCounter() {
        var r = registry(accounts: 2)
        let h = SHA256.hash([1])
        XCTAssertEqual(r.verify(assertion(1, hash: h), expectedClientDataHash: h, principal: PrincipalID("a"), verifier: verifier), .accepted)
        XCTAssertEqual(r.verify(assertion(2, hash: h), expectedClientDataHash: h, principal: PrincipalID("b"), verifier: verifier), .accepted)
        XCTAssertEqual(r.verify(assertion(3, hash: h), expectedClientDataHash: h, principal: PrincipalID("c"), verifier: verifier), .accountLimitExceeded(limit: 2))
        XCTAssertEqual(r.verify(assertion(3, hash: h), expectedClientDataHash: h, principal: PrincipalID("a"), verifier: verifier), .accepted,
                       "counter 3 was not consumed by the refused account")
        XCTAssertEqual(r.records[DeviceKeyID("k")]?.accounts, [PrincipalID("a"), PrincipalID("b")])
    }
}
