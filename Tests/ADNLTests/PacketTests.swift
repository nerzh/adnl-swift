import Foundation
import XCTest
import adnl_swift

final class PacketTests: XCTestCase {
    func testEveryUndersizedBodyThrowsAsSoonAsHeaderIsAvailable() {
        for size in UInt8(0)..<64 {
            let header = Data([size, 0, 0, 0])
            for input in [header, header + Data(repeating: 0, count: Int(size))] {
                for data in [input, nonzeroSlice(input)] {
                    assertADNLError("at least 64") { try ADNLPacket.parse(data: data) }
                }
            }
        }
    }

    func testEveryTruncatedValidPacketReturnsNil() throws {
        for payload in [Data(), Data(0..<127)] {
            let packet = try ADNLPacket(payload: payload, nonce: Data(0..<32))
            for count in 0..<packet.length {
                let prefix = Data(packet.data.prefix(count))
                XCTAssertNil(try ADNLPacket.parse(data: prefix), "Prefix length: \(count)")
                XCTAssertNil(try ADNLPacket.parse(data: nonzeroSlice(prefix)))
            }
        }
        XCTAssertNil(try ADNLPacket.parse(data: hex("ffffffff")))
        XCTAssertNil(try ADNLPacket.parse(data: hex("40000000")))
    }

    func testValidPacketsAndSlicesRoundTrip() throws {
        for payload in [Data(), Data(0..<255), Data(repeating: 0x92, count: 1024)] {
            let packet = try ADNLPacket(payload: nonzeroSlice(payload), nonce: nonzeroSlice(Data(0..<32)))
            for input in [packet.data, nonzeroSlice(packet.data)] {
                let parsed = try XCTUnwrap(ADNLPacket.parse(data: input))
                XCTAssertEqual(parsed.payload, payload)
                XCTAssertEqual(parsed.nonce, Data(0..<32))
                XCTAssertEqual(parsed.length, input.count)
                XCTAssertEqual(parsed.data, packet.data)
                XCTAssertEqual(parsed.nonce.startIndex, 0)
                XCTAssertEqual(parsed.payload.startIndex, 0)
            }
        }
    }

    func testConcatenatedPacketsCanBeParsedAfterRemovingFirst() throws {
        let first = ADNLPacket(payload: Data([1]))
        let second = ADNLPacket(payload: Data([2, 3]))
        var buffer = first.data + second.data
        XCTAssertEqual(try ADNLPacket.parse(data: buffer)?.payload, first.payload)
        buffer.removeFirst(first.length)
        XCTAssertGreaterThan(buffer.startIndex, 0)
        XCTAssertEqual(try ADNLPacket.parse(data: buffer)?.payload, second.payload)
    }

    func testCorruptedNoncePayloadOrChecksumThrows() throws {
        let packet = try ADNLPacket(payload: Data([1, 2, 3]), nonce: Data(0..<32))
        for index in [4, 35, 36, 38, 39, packet.length - 1] {
            var corrupted = packet.data
            corrupted[index] ^= 1
            for data in [corrupted, nonzeroSlice(corrupted)] {
                assertADNLError("Bad packet hash") { try ADNLPacket.parse(data: data) }
            }
        }
    }

    func testNonceLengthIsValidatedWithoutTruncation() throws {
        for count in [0, 1, 31, 33, 64] {
            assertADNLError("nonce must be exactly 32 bytes, received \(count)") {
                try ADNLPacket(payload: Data(), nonce: nonzeroSlice(Data(repeating: 1, count: count)))
            }
        }
        let packet = ADNLPacket(payload: Data())
        XCTAssertEqual(packet.nonce.count, 32)
        XCTAssertEqual(packet.data.count, 68)
        XCTAssertEqual(packet.size, hex("40000000"))
        XCTAssertEqual(try ADNLPacket.parse(data: packet.data)?.payload, Data())
    }
}
