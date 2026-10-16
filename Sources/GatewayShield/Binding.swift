/// An account on the gateway (the thing budgets and risk are tracked against).
public struct PrincipalID: Hashable, Sendable, Comparable, CustomStringConvertible {
    public let rawValue: String
    public init(_ rawValue: String) { self.rawValue = rawValue }
    public static func < (l: Self, r: Self) -> Bool { l.rawValue < r.rawValue }
    public var description: String { rawValue }
}

/// An App Attest key id: one per app install, generated in the Secure Enclave.
public struct DeviceKeyID: Hashable, Sendable, Comparable, CustomStringConvertible {
    public let rawValue: String
    public init(_ rawValue: String) { self.rawValue = rawValue }
    public static func < (l: Self, r: Self) -> Bool { l.rawValue < r.rawValue }
    public var description: String { rawValue }
}

/// What the client is asking the model to do. Everything here is covered by the
/// device assertion, so a proxy in the middle cannot raise `maxOutputTokens` or
/// swap the prompt without failing verification.
public struct PromptPayload: Hashable, Sendable {
    public let prompt: String
    public let maxOutputTokens: Int

    public init(prompt: String, maxOutputTokens: Int) {
        self.prompt = prompt
        self.maxOutputTokens = maxOutputTokens
    }

    /// Canonical body bytes (length-prefixed, so field boundaries can't shift).
    public var canonicalBody: [UInt8] {
        var w = CanonicalWriter(domain: "gateway-shield/v1/payload")
        w.field(Array(prompt.utf8))
        w.field(maxOutputTokens)
        return w.bytes
    }
}

/// Length-prefixed, domain-separated encoding.
///
/// Plain concatenation is ambiguous (`"ab" + "c"` and `"a" + "bc"` hash the same),
/// which would let an attacker move bytes between the principal and the prompt
/// and keep a valid signature. Each field is written as an 8-byte big-endian
/// length followed by its bytes.
public struct CanonicalWriter: Sendable {
    public private(set) var bytes: [UInt8] = []

    public init(domain: String) { field(Array(domain.utf8)) }

    public mutating func field(_ value: [UInt8]) {
        // `count` is never negative, so the conversion cannot trap.
        let length = UInt64(value.count)
        for shift in stride(from: 56, through: 0, by: -8) {
            bytes.append(UInt8(truncatingIfNeeded: length >> UInt64(shift)))
        }
        bytes.append(contentsOf: value)
    }

    public mutating func field(_ value: Int) {
        // Two's-complement bit pattern, sign-extended to 64 bits on every platform.
        let pattern = UInt64(bitPattern: Int64(value))
        var raw: [UInt8] = []
        for shift in stride(from: 56, through: 0, by: -8) {
            raw.append(UInt8(truncatingIfNeeded: pattern >> UInt64(shift)))
        }
        field(raw)
    }
}

/// Binds an assertion to one challenge, one principal and one exact request.
public enum RequestBinding {
    public static func clientDataHash(
        challenge: [UInt8],
        principal: PrincipalID,
        path: String,
        payload: PromptPayload
    ) -> SHA256Digest {
        var w = CanonicalWriter(domain: "gateway-shield/v1/request")
        w.field(challenge)
        w.field(Array(principal.rawValue.utf8))
        w.field(Array(path.utf8))
        w.field(SHA256.hash(payload.canonicalBody).bytes)
        return SHA256.hash(w.bytes)
    }
}

/// A device assertion, shaped like App Attest's: a per-key counter that the
/// Secure Enclave increments on every signature, the hash of the client data,
/// and a signature over both.
public struct Assertion: Hashable, Sendable {
    public let keyID: DeviceKeyID
    public let counter: UInt32
    public let clientDataHash: SHA256Digest
    public let signature: [UInt8]

    public init(keyID: DeviceKeyID, counter: UInt32, clientDataHash: SHA256Digest, signature: [UInt8]) {
        self.keyID = keyID
        self.counter = counter
        self.clientDataHash = clientDataHash
        self.signature = signature
    }

    /// The exact bytes the signature covers.
    public static func signedMessage(counter: UInt32, clientDataHash: SHA256Digest) -> [UInt8] {
        var w = CanonicalWriter(domain: "gateway-shield/v1/assertion")
        w.field(Int(counter))   // UInt32 always fits in Int64's range
        w.field(clientDataHash.bytes)
        return w.bytes
    }
}

/// Verifies a signature with a registered public key.
///
/// Production: P-256 ECDSA over App Attest's `authenticatorData || clientDataHash`
/// (CryptoKit `P256.Signing.PublicKey.isValidSignature`). This package ships
/// only the simulated scheme below so it can run on Linux CI with no dependencies.
public protocol AssertionSignatureVerifier: Sendable {
    func isValidSignature(_ signature: [UInt8], over message: [UInt8], publicKey: [UInt8]) -> Bool
}

/// A deliberately insecure stand-in used by the lab and the tests: the "public
/// key" is the secret itself and the signature is a keyed hash. It is good enough
/// to show that the gateway rejects a forged or mismatched signature; it is not a
/// signature scheme and must never be used outside a simulation.
public struct InsecureSimulatedSignature: AssertionSignatureVerifier {
    public init() {}

    public static func sign(_ message: [UInt8], secret: [UInt8]) -> [UInt8] {
        var w = CanonicalWriter(domain: "gateway-shield/v1/simulated-signature")
        w.field(secret)
        w.field(message)
        return SHA256.hash(w.bytes).bytes
    }

    public func isValidSignature(_ signature: [UInt8], over message: [UInt8], publicKey: [UInt8]) -> Bool {
        Self.sign(message, secret: publicKey) == signature
    }
}
