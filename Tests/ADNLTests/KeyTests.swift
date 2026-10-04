import Foundation
import XCTest
import adnl_swift

final class KeyTests: XCTestCase {
    func testIndependentPublicKeyAndConversionVectors() throws {
        for vector in keyVectors {
            for seed in [vector.seed, nonzeroSlice(vector.seed)] {
                XCTAssertEqual(try Ed25519Wrapper.getPublicKey(privateKey: seed), vector.publicKey)
                XCTAssertEqual(try Ed25519Wrapper.convertEd25519ToX25519(ed25519PrivateKey: seed), vector.scalar)
            }
            for publicKey in [vector.publicKey, nonzeroSlice(vector.publicKey)] {
                let converted = try Ed25519Wrapper.edwardsToMontgomery(bytesData: publicKey)
                XCTAssertEqual(converted.count, 32)
                XCTAssertEqual(converted, vector.montgomery)
            }
            var oppositeSign = vector.publicKey
            oppositeSign[31] ^= 0x80
            XCTAssertEqual(try Ed25519Wrapper.edwardsToMontgomery(bytesData: oppositeSign), vector.montgomery)
        }
        // The Edwards base point maps to u = 9; output must retain zero padding.
        XCTAssertEqual(try Ed25519Wrapper.edwardsToMontgomery(bytesData: hex("58" + String(repeating: "66", count: 31))),
                       Data([9]) + Data(repeating: 0, count: 31))
    }

    func testIndependentSharedSecretsInBothDirectionsAndWithSlices() throws {
        for (a, b, expected) in sharedVectors {
            for (local, peer) in [(keyVectors[a], keyVectors[b]), (keyVectors[b], keyVectors[a])] {
                XCTAssertEqual(try Ed25519Wrapper.getSharedKey(privateKey: local.seed, publicKey: peer.publicKey), expected)
                let keys = try ADNLKeys(privateKey: nonzeroSlice(local.seed), peerPublicKey: nonzeroSlice(peer.publicKey))
                XCTAssertEqual(keys.sharedSecret, expected)
                XCTAssertEqual(keys.public, local.publicKey)
                XCTAssertEqual(keys.peerPublic, peer.publicKey)
                XCTAssertEqual(keys.peerPublic.startIndex, 0)
            }
        }
    }

    func testInvalidPrivateSeedLengthsThrowAtEveryBoundary() {
        for count in Array(0..<32) + [33, 64, 65] {
            let invalid = nonzeroSlice(Data(repeating: 7, count: count))
            let message = "private seed must be exactly 32 bytes, received \(count)"
            assertADNLError(message) { try Ed25519Wrapper.getPublicKey(privateKey: invalid) }
            assertADNLError(message) { try Ed25519Wrapper.convertEd25519ToX25519(ed25519PrivateKey: invalid) }
            assertADNLError(message) { try Ed25519Wrapper.getSharedKey(privateKey: invalid, publicKey: keyVectors[0].publicKey) }
            assertADNLError(message) { try ADNLKeys(privateKey: invalid, peerPublicKey: keyVectors[0].publicKey) }
            if count > 0 {
                assertADNLError(message) {
                    try ADNLKeys(privateKey: invalid.base64EncodedString(), peerPublicKey: keyVectors[0].publicKey.base64EncodedString())
                }
            }
        }
    }

    func testInvalidPublicKeyLengthsThrowAtEveryBoundary() {
        for count in Array(0..<32) + [33, 64, 65] {
            let invalid = nonzeroSlice(Data(repeating: 7, count: count))
            let message = "public key must be exactly 32 bytes, received \(count)"
            assertADNLError(message) { try Ed25519Wrapper.edwardsToMontgomery(bytesData: invalid) }
            assertADNLError(message) { try Ed25519Wrapper.getSharedKey(privateKey: keyVectors[0].seed, publicKey: invalid) }
            assertADNLError(message) { try ADNLKeys(privateKey: keyVectors[0].seed, peerPublicKey: invalid) }
            assertADNLError(message) { try ADNLKeys(peerPublicKey: invalid) }
            assertADNLError(message) { try ADNLAddress(publicKey: invalid) }
            assertADNLError(message) { try ADNLAddress(publicKey: Array(invalid)) }
            if count > 0 {
                assertADNLError(message) { try ADNLKeys(peerPublicKey: invalid.base64EncodedString()) }
                assertADNLError(message) { try ADNLAddress(publicKey: invalid.base64EncodedString()) }
            }
        }
    }

    func testNoncanonicalCoordinatesAreRejectedByConversionAndExchange() {
        for lowByte in UInt8(0xed)...UInt8(0xff) {
            for sign: UInt8 in [0, 0x80] {
                var key = Data(repeating: 0xff, count: 32)
                key[0] = lowByte
                key[31] = 0x7f | sign
                for input in [key, nonzeroSlice(key)] {
                    assertADNLError("y-coordinate must be less than") {
                        try Ed25519Wrapper.edwardsToMontgomery(bytesData: input)
                    }
                    assertADNLError("y-coordinate must be less than") {
                        try Ed25519Wrapper.getSharedKey(privateKey: keyVectors[0].seed, publicKey: input)
                    }
                    assertADNLError("y-coordinate must be less than") {
                        try ADNLKeys(privateKey: keyVectors[0].seed, peerPublicKey: input)
                    }
                }
            }
        }
    }

    func testUndefinedCoordinatesAreRejectedByConversionAndExchange() {
        for sign: UInt8 in [0, 0x80] {
            var key = Data([1]) + Data(repeating: 0, count: 31)
            key[31] = sign
            for input in [key, nonzeroSlice(key)] {
                assertADNLError("undefined for Ed25519 y = 1") {
                    try Ed25519Wrapper.edwardsToMontgomery(bytesData: input)
                }
                assertADNLError("undefined for Ed25519 y = 1") {
                    try Ed25519Wrapper.getSharedKey(privateKey: keyVectors[0].seed, publicKey: input)
                }
            }
        }
    }

    func testZeroSharedSecretsAreRejected() {
        for key in [Data(repeating: 0, count: 32),
                    hex("ec" + String(repeating: "ff", count: 30) + "7f")] {
            for input in [key, nonzeroSlice(key)] {
                assertADNLError("all-zero shared secret") {
                    try Ed25519Wrapper.getSharedKey(privateKey: keyVectors[0].seed, publicKey: input)
                }
                assertADNLError("all-zero shared secret") {
                    try ADNLKeys(privateKey: keyVectors[0].seed, peerPublicKey: input)
                }
            }
        }
    }

    func testValidAddressAndStringKeys() throws {
        let vector = keyVectors[0]
        let expected = try ADNLAddress(publicKey: vector.publicKey).hash
        XCTAssertEqual(try ADNLAddress(publicKey: nonzeroSlice(vector.publicKey)).hash, expected)
        XCTAssertEqual(try ADNLAddress(publicKey: Array(vector.publicKey)).hash, expected)
        XCTAssertEqual(try ADNLAddress(publicKey: vector.publicKey.base64EncodedString()).hash, expected)
        let keys = try ADNLKeys(privateKey: vector.seed.base64EncodedString(), peerPublicKey: keyVectors[1].publicKey.base64EncodedString())
        XCTAssertEqual(keys.sharedSecret, sharedVectors[0].2)
        XCTAssertEqual(try ADNLKeys(peerPublicKey: vector.publicKey).sharedSecret.count, 32)
    }
}
