import Foundation
import XCTest
import adnl_swift

final class HandshakeTests: XCTestCase {
    private func makeClient() throws -> ADNLCipher {
        try ADNLCipher(serverSecret: keyVectors[0].seed.base64EncodedString(),
                       peerPubKey: keyVectors[1].publicKey.base64EncodedString(),
                       paramsData: Data(0..<160).base64EncodedString(), mode: .client)
    }

    func testValidHandshakeAndSlices() throws {
        let client = try makeClient()
        let data = try ADNLHandshake.adnlHandshake(keys: client.keys, params: client.params, address: client.address)
        XCTAssertEqual(data.count, 256)
        let expectedNodeID = try ADNLAddress(publicKey: keyVectors[1].publicKey).hash
        for input in [data, nonzeroSlice(data)] {
            let request = try ADNLHandshake.adnlParseHandshake(input)
            XCTAssertEqual(request.shortLocalNodeId, expectedNodeID)
            XCTAssertEqual(request.senderPubKey, keyVectors[0].publicKey)
            XCTAssertEqual(request.checkSum, client.params.hash)
            XCTAssertEqual(request.encryptedData.count, 160)
            for field in [request.shortLocalNodeId, request.senderPubKey, request.checkSum, request.encryptedData] {
                XCTAssertEqual(field.startIndex, 0)
            }
            let server = try ADNLHandshake.adnlHandshakeAssets(input, secretKey: keyVectors[1].seed.base64EncodedString())
            XCTAssertEqual(server.params.bytes, client.params.bytes)
            XCTAssertEqual(server.keys.sharedSecret, sharedVectors[0].2)
            XCTAssertEqual(server.encryptor.key, client.decryptor.key)
            XCTAssertEqual(server.decryptor.key, client.encryptor.key)
            XCTAssertEqual(server.encryptor.iv, client.decryptor.iv)
            XCTAssertEqual(server.decryptor.iv, client.encryptor.iv)
        }
    }

    func testEveryTruncatedOrOversizedHandshakeThrows() throws {
        let client = try makeClient()
        let valid = try ADNLHandshake.adnlHandshake(keys: client.keys, params: client.params, address: client.address)
        for count in 0..<256 {
            assertADNLError("must be 256 bytes") {
                try ADNLHandshake.adnlParseHandshake(nonzeroSlice(Data(valid.prefix(count))))
            }
        }
        assertADNLError("must be 256 bytes") { try ADNLHandshake.adnlParseHandshake(valid + Data([0])) }
    }

    func testWrongRecipientChecksumAndEncryptedParametersAreRejected() throws {
        let client = try makeClient()
        let valid = try ADNLHandshake.adnlHandshake(keys: client.keys, params: client.params, address: client.address)
        for index in [0, 64, 95, 96, 255] {
            var corrupted = valid
            corrupted[index] ^= 1
            assertADNLError(index == 0 ? "ADNLAddress is not valid" : "ADNLAESParams is not valid") {
                try ADNLHandshake.adnlHandshakeAssets(nonzeroSlice(corrupted), secretKey: keyVectors[1].seed.base64EncodedString())
            }
        }
    }

    func testConsecutivePacketsInBothDirections() throws {
        let client = try makeClient()
        let handshake = try ADNLHandshake.adnlHandshake(keys: client.keys, params: client.params, address: client.address)
        let server = try ADNLHandshake.adnlHandshakeAssets(handshake, secretKey: keyVectors[1].seed.base64EncodedString())
        for length in [0, 1, 15, 16, 17, 257] {
            let payload = Data(repeating: UInt8(truncatingIfNeeded: length), count: length)
            let request = try client.encryptor.adnlSerializeMessage(data: payload)
            XCTAssertEqual(try server.decryptor.adnlDeserializeMessage(data: nonzeroSlice(request)), payload)
            let response = try server.encryptor.adnlSerializeMessage(data: payload)
            XCTAssertEqual(try client.decryptor.adnlDeserializeMessage(data: nonzeroSlice(response)), payload)
        }
    }

    func testFragmentedEncryptedPacketStream() throws {
        let client = try makeClient()
        let handshake = try ADNLHandshake.adnlHandshake(keys: client.keys, params: client.params, address: client.address)
        let server = try ADNLHandshake.adnlHandshakeAssets(handshake, secretKey: keyVectors[1].seed.base64EncodedString())
        let messages = [Data(), Data([1, 2, 3]), Data(0..<255)]
        var encrypted = Data()
        for message in messages {
            encrypted.append(try client.encryptor.adnlSerializeMessage(data: message))
        }
        var pending = Data()
        var received: [Data] = []
        for offset in stride(from: 0, to: encrypted.count, by: 7) {
            pending.append(try server.decryptor.update(nonzeroSlice(Data(encrypted.dropFirst(offset).prefix(7)))))
            while let packet = try ADNLPacket.parse(data: pending) {
                received.append(packet.payload)
                pending.removeFirst(packet.length)
            }
        }
        XCTAssertEqual(received, messages)
        XCTAssertTrue(pending.isEmpty)
    }

    func testAESParametersAcceptSlicesAndRejectWrongLengths() throws {
        let params = try ADNLAESParams(nonzeroSlice(Data(0..<160)))
        XCTAssertEqual(params.bytes, Array(0..<160))
        XCTAssertEqual(params.rxKey, Array(0..<32))
        XCTAssertEqual(params.txKey, Array(32..<64))
        XCTAssertEqual(params.rxNonce, Array(64..<80))
        XCTAssertEqual(params.txNonce, Array(80..<96))
        XCTAssertEqual(params.padding, Array(96..<160))
        for count in [0, 159, 161] {
            XCTAssertThrowsError(try ADNLAESParams(nonzeroSlice(Data(repeating: 0, count: count))))
        }
    }
}
