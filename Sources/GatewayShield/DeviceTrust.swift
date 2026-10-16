// MARK: - Challenges

public enum ChallengeVerdict: Equatable, Sendable {
    case fresh
    /// Never issued, already used, or evicted under capacity pressure.
    case unknownOrUsed
    case expired
}

/// Single-use, short-lived server nonces.
///
/// Bounded: when `capacity` outstanding challenges exist, the oldest is evicted.
/// A client holding an evicted challenge gets `.unknownOrUsed` and fetches a
/// fresh one, which costs one round trip; the alternative (unbounded growth on a
/// public endpoint that anyone can hit) costs the server.
public struct ChallengeStore: Sendable {
    public let ttl: Millis
    public let capacity: Int
    public private(set) var evictedUnused = 0

    private var outstanding: [[UInt8]: Millis] = [:]   // bytes -> expiresAt
    private var order: [[UInt8]] = []                   // FIFO of issue order
    private var head = 0

    public init(ttl: Millis, capacity: Int) {
        self.ttl = max(1, ttl)
        self.capacity = max(1, capacity)
    }

    public var outstandingCount: Int { outstanding.count }
    /// Entries held in the issue-order queue, live or dead (for memory tests).
    var orderStorageCount: Int { order.count - head }

    public mutating func insert(_ bytes: [UInt8], now: Millis) -> Millis {
        let expiresAt = Saturating.add(now, ttl)
        outstanding[bytes] = expiresAt
        order.append(bytes)
        // Drop entries that are already expired or consumed from the front, then
        // enforce the capacity bound.
        while head < order.count {
            let front = order[head]   // head < order.count checked by the loop
            if let exp = outstanding[front] {
                if exp <= now {
                    outstanding[front] = nil
                } else if outstanding.count > capacity {
                    outstanding[front] = nil
                    evictedUnused += 1
                } else {
                    break
                }
            }
            head += 1
        }
        // Consumed entries behind a live front entry are never popped by the loop
        // above, so `order` could otherwise grow with every issue-and-consume
        // cycle while one abandoned challenge sits at the front. Rebuild it from
        // the live entries once it holds more than twice the capacity: at least
        // half of it is dead by then, so the rebuild is amortised O(1).
        if order.count - head > max(64, Saturating.multiply(capacity, 2)) {
            order = order[head...].filter { outstanding[$0] != nil }
            head = 0
        } else if head > 64, head * 2 > order.count {
            order.removeFirst(head)
            head = 0
        }
        return expiresAt
    }

    /// Consumes the challenge whatever the verdict: a challenge is good for
    /// exactly one attempt, so a failed request cannot be replayed with it.
    public mutating func consume(_ bytes: [UInt8], now: Millis) -> ChallengeVerdict {
        guard let expiresAt = outstanding.removeValue(forKey: bytes) else { return .unknownOrUsed }
        return now < expiresAt ? .fresh : .expired
    }
}

// MARK: - Replay window

public enum ReplayCheck: Equatable, Sendable {
    case fresh
    case duplicate
    case tooOld
}

/// An RFC 4303-style anti-replay window over the App Attest assertion counter.
///
/// App Attest's guidance is "reject any counter not greater than the stored one".
/// That breaks the moment one device sends two requests concurrently: they can
/// arrive in the opposite order to the one they were signed in, and the second
/// legitimate request is rejected as a replay. A 64-wide window accepts any
/// counter it has not seen within 64 of the highest, and still rejects every
/// duplicate.
public struct ReplayWindow: Sendable, Equatable {
    public static let width: UInt32 = 64

    public private(set) var highest: UInt32
    /// Bit `i` set means `highest - i` has been accepted.
    private var seen: UInt64

    /// `attestationCounter` is the counter at attestation time (0 for App Attest),
    /// which is treated as already used.
    public init(attestationCounter: UInt32 = 0) {
        highest = attestationCounter
        seen = 1
    }

    public func check(_ counter: UInt32) -> ReplayCheck {
        if counter > highest { return .fresh }
        let distance = highest - counter          // counter <= highest: no underflow
        if distance >= Self.width { return .tooOld }
        return seen & (UInt64(1) << UInt64(distance)) != 0 ? .duplicate : .fresh
    }

    /// Records a counter that `check` reported `.fresh`. Returns `false` (and
    /// changes nothing) for anything else.
    @discardableResult
    public mutating func record(_ counter: UInt32) -> Bool {
        guard check(counter) == .fresh else { return false }
        if counter > highest {
            let shift = counter - highest
            seen = shift >= Self.width ? 1 : (seen << UInt64(shift)) | 1
            highest = counter
        } else {
            seen |= UInt64(1) << UInt64(highest - counter)
        }
        return true
    }
}

// MARK: - Key registry

public enum AssertionVerdict: Equatable, Sendable {
    case accepted
    case unknownKey
    case revokedKey
    case bindingMismatch
    case replayed(ReplayCheck)
    case badSignature
    /// One device key is being used for more accounts than policy allows
    /// (an account farm on one phone).
    case accountLimitExceeded(limit: Int)
}

public enum RegistrationResult: Equatable, Sendable {
    case registered
    case alreadyRegistered
    case registryFull
}

/// Attested device keys and what each has been used for.
public struct KeyRegistry: Sendable {
    public struct Record: Sendable, Equatable {
        public let keyID: DeviceKeyID
        public let publicKey: [UInt8]
        public fileprivate(set) var window: ReplayWindow
        public fileprivate(set) var revoked = false
        public fileprivate(set) var accounts: [PrincipalID] = []
    }

    public let maxAccountsPerKey: Int
    public let maxKeys: Int
    public private(set) var records: [DeviceKeyID: Record] = [:]

    public init(maxAccountsPerKey: Int, maxKeys: Int) {
        self.maxAccountsPerKey = max(1, maxAccountsPerKey)
        self.maxKeys = max(1, maxKeys)
    }

    /// Called after the attestation object has been verified (certificate chain to
    /// Apple's App Attest root, app id, nonce). That verification is out of scope
    /// here; this records its result.
    public mutating func register(_ keyID: DeviceKeyID, publicKey: [UInt8]) -> RegistrationResult {
        guard records[keyID] == nil else { return .alreadyRegistered }
        guard records.count < maxKeys else { return .registryFull }
        records[keyID] = Record(keyID: keyID, publicKey: publicKey, window: ReplayWindow())
        return .registered
    }

    public mutating func revoke(_ keyID: DeviceKeyID) {
        records[keyID]?.revoked = true
    }

    /// Verifies an assertion and, only if every check passes, records its counter.
    ///
    /// Ordering matters. The counter is recorded last, after the signature: if it
    /// were recorded first, anyone could send an unsigned assertion with counter
    /// `UInt32.max` and permanently lock the real device out.
    public mutating func verify(
        _ assertion: Assertion,
        expectedClientDataHash: SHA256Digest,
        principal: PrincipalID,
        verifier: any AssertionSignatureVerifier
    ) -> AssertionVerdict {
        guard var record = records[assertion.keyID] else { return .unknownKey }
        guard !record.revoked else { return .revokedKey }
        guard assertion.clientDataHash == expectedClientDataHash else { return .bindingMismatch }
        let replay = record.window.check(assertion.counter)
        guard replay == .fresh else { return .replayed(replay) }
        let message = Assertion.signedMessage(counter: assertion.counter, clientDataHash: assertion.clientDataHash)
        guard verifier.isValidSignature(assertion.signature, over: message, publicKey: record.publicKey) else {
            return .badSignature
        }
        if !record.accounts.contains(principal) {
            guard record.accounts.count < maxAccountsPerKey else {
                return .accountLimitExceeded(limit: maxAccountsPerKey)
            }
            record.accounts.append(principal)
        }
        record.window.record(assertion.counter)
        records[assertion.keyID] = record
        return .accepted
    }
}
