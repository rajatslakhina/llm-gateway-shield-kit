import XCTest
@testable import GatewayShield

final class SaturatingTests: XCTestCase {
    func testAddSubtractMultiplySaturateInsteadOfTrapping() {
        XCTAssertEqual(Saturating.add(Int.max, 1), Int.max)
        XCTAssertEqual(Saturating.add(Int.min, -1), Int.min)
        XCTAssertEqual(Saturating.add(2, 3), 5)
        XCTAssertEqual(Saturating.subtract(Int.min, 1), Int.min)
        XCTAssertEqual(Saturating.subtract(Int.max, -1), Int.max)
        XCTAssertEqual(Saturating.subtract(0, Int.min), Int.max)
        XCTAssertEqual(Saturating.multiply(Int.max, 2), Int.max)
        XCTAssertEqual(Saturating.multiply(Int.min, 2), Int.min)
        XCTAssertEqual(Saturating.multiply(Int.min, -1), Int.max)
        XCTAssertEqual(Saturating.multiply(-3, 4), -12)
    }

    func testDivisionNeverTraps() {
        XCTAssertNil(Saturating.divide(5, 0))
        XCTAssertEqual(Saturating.divide(Int.min, -1), Int.max)
        XCTAssertEqual(Saturating.divide(7, 2), 3)
        XCTAssertEqual(Saturating.ceilDivide(7, 2), 4)
        XCTAssertEqual(Saturating.ceilDivide(8, 2), 4)
        XCTAssertEqual(Saturating.ceilDivide(0, 5), 0)
        XCTAssertNil(Saturating.ceilDivide(-1, 2))
        XCTAssertNil(Saturating.ceilDivide(1, 0))
        XCTAssertEqual(Saturating.ceilDivide(Int.max, 1), Int.max)
    }

    func testClampHandlesInvertedRange() {
        XCTAssertEqual(Saturating.clamp(5, 0, 10), 5)
        XCTAssertEqual(Saturating.clamp(-5, 0, 10), 0)
        XCTAssertEqual(Saturating.clamp(50, 0, 10), 10)
        XCTAssertEqual(Saturating.clamp(50, 10, 0), 10, "lower bound wins when the range is inverted")
    }
}

final class SHA256Tests: XCTestCase {
    private func hex(_ s: [UInt8]) -> String { SHA256.hash(s).hex }

    func testNISTAndPaddingBoundaryVectors() {
        XCTAssertEqual(hex([]), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        XCTAssertEqual(hex(Array("abc".utf8)), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        XCTAssertEqual(hex(Array("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8)),
                       "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        // 55, 56 and 64 bytes straddle the one-block / two-block padding boundary.
        XCTAssertEqual(hex(Array(repeating: 0x61, count: 55)), "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318")
        XCTAssertEqual(hex(Array(repeating: 0x61, count: 56)), "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a")
        XCTAssertEqual(hex(Array(repeating: 0x61, count: 64)), "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb")
    }

    func testOneMillionAs() {
        XCTAssertEqual(hex(Array(repeating: 0x61, count: 1_000_000)),
                       "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
    }
}

final class BindingTests: XCTestCase {
    func testCanonicalEncodingIsNotAmbiguous() {
        var a = CanonicalWriter(domain: "t"); a.field(Array("ab".utf8)); a.field(Array("c".utf8))
        var b = CanonicalWriter(domain: "t"); b.field(Array("a".utf8)); b.field(Array("bc".utf8))
        XCTAssertNotEqual(a.bytes, b.bytes)
        XCTAssertNotEqual(SHA256.hash(a.bytes), SHA256.hash(b.bytes))
    }

    func testEveryBoundFieldChangesTheHash() {
        let challenge: [UInt8] = [1, 2, 3]
        let payload = PromptPayload(prompt: "hello", maxOutputTokens: 100)
        let base = RequestBinding.clientDataHash(challenge: challenge, principal: PrincipalID("p"), path: "/v1", payload: payload)
        let variants = [
            RequestBinding.clientDataHash(challenge: [1, 2, 4], principal: PrincipalID("p"), path: "/v1", payload: payload),
            RequestBinding.clientDataHash(challenge: challenge, principal: PrincipalID("q"), path: "/v1", payload: payload),
            RequestBinding.clientDataHash(challenge: challenge, principal: PrincipalID("p"), path: "/v2", payload: payload),
            RequestBinding.clientDataHash(challenge: challenge, principal: PrincipalID("p"), path: "/v1",
                                          payload: PromptPayload(prompt: "hellO", maxOutputTokens: 100)),
            RequestBinding.clientDataHash(challenge: challenge, principal: PrincipalID("p"), path: "/v1",
                                          payload: PromptPayload(prompt: "hello", maxOutputTokens: 101)),
        ]
        for v in variants { XCTAssertNotEqual(v, base) }
        XCTAssertEqual(Set(variants).count, variants.count)
    }

    func testNegativeAndExtremeIntsEncodeWithoutTrapping() {
        var w = CanonicalWriter(domain: "t")
        w.field(Int.min); w.field(Int.max); w.field(-1)
        XCTAssertEqual(w.bytes.count, 9 + 3 * 16)   // domain "t" (8+1), then three 8-byte lengths + 8-byte values
        var v = CanonicalWriter(domain: "t"); v.field(-1)
        XCTAssertEqual(Array(v.bytes.suffix(8)), Array(repeating: 0xff, count: 8), "two's complement, sign-extended")
    }
}
