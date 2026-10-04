import Foundation
import XCTest
import adnl_swift

func hex(_ value: String) -> Data {
    let chars = Array(value.filter { !$0.isWhitespace })
    precondition(chars.count.isMultiple(of: 2))
    return Data(stride(from: 0, to: chars.count, by: 2).map {
        UInt8(String(chars[$0...($0 + 1)]), radix: 16)!
    })
}

func nonzeroSlice(_ data: Data) -> Data {
    let padded = Data(repeating: 0xa5, count: 19) + data
    return padded.dropFirst(19)
}

func assertADNLError<T>(_ message: String, file: StaticString = #filePath, line: UInt = #line,
                        _ operation: () throws -> T) {
    XCTAssertThrowsError(try operation(), file: file, line: line) { error in
        guard let error = error as? ADNLError else {
            return XCTFail("Unexpected error: \(error)", file: file, line: line)
        }
        XCTAssertTrue(error.reason.contains(message), error.reason, file: file, line: line)
    }
}

func assertADNLError<T>(_ message: String, file: StaticString = #filePath, line: UInt = #line,
                        _ operation: () async throws -> T) async {
    do {
        _ = try await operation()
        XCTFail("Expected ADNLError", file: file, line: line)
    } catch let error as ADNLError {
        XCTAssertTrue(error.reason.contains(message), error.reason, file: file, line: line)
    } catch {
        XCTFail("Unexpected error: \(error)", file: file, line: line)
    }
}

// RFC 8032 section 7.1 seeds/public keys and libsodium's ed25519_convert seed.
// X25519 outputs were independently generated with libsodium 1.0.20.
let keyVectors: [(seed: Data, publicKey: Data, montgomery: Data, scalar: Data)] = [
    (
        hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
        hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
        hex("d85e07ec22b0ad881537c2f44d662d1a143cf830c57aca4305d85c7a90f6b62e"),
        hex("307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f")
    ),
    (
        hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
        hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
        hex("25c704c594b88afc00a76b69d1ed2b984d7e22550f3ed0802d04fbcd07d38d47"),
        hex("68bd9ed75882d52815a97585caf4790a7f6c6b3b7f821c5e259a24b02e502e51")
    ),
    (
        hex("421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee"),
        hex("b5076a8474a832daee4dd5b4040983b6623b5f344aca57d4d6ee4baf3f259e6e"),
        hex("f1814f0e8ff1043d8a44d25babff3cedcae6c22c3edaa48f857ae70de2baae50"),
        hex("8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166")
    )
]

let sharedVectors: [(Int, Int, Data)] = [
    (0, 1, hex("5166f24a6918368e2af831a4affadd97af0ac326bdf143596c045967cc00230e")),
    (0, 2, hex("7f19aee0fce03d5068dceef0ae6bcbe10042087dda5251b3256a32daa1c25a61")),
    (1, 2, hex("adbc15c2b1a873407e9e36401612830e4bc6ec48a1bdbf5a674773d6c80a6b66"))
]
