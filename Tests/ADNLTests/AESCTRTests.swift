import Foundation
import XCTest
import adnl_swift

final class AESCTRTests: XCTestCase {
    // NIST SP 800-38A, section F.5.5: CTR-AES256.Encrypt.
    private let key = hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    private let iv = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    private let plaintext = hex("""
        6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51
        30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710
        """)
    private let ciphertext = hex("""
        601ec313775789a5b7a7f504bbf3d228 f443e3ca4d62b59aca84e990cacaf5c5
        2b0930daa23de94ce87017ba2d84988d dfc9c58db67aada613c2dd08457941a6
        """)

    func testNISTVectorInBothDirections() throws {
        let encryptor = try AESADNL(key: Array(key), iv: Array(iv), mode: .encryptor)
        XCTAssertEqual(try encryptor.update(plaintext, isLast: true), ciphertext)
        let decryptor = try AESADNL(key: Array(key), iv: Array(iv), mode: .decryptor)
        XCTAssertEqual(try decryptor.update(ciphertext, isLast: true), plaintext)
    }

    func testEverySplitPreservesCounterAndPartialBlockState() throws {
        for mode in [AESADNL.Mode.encryptor, .decryptor] {
            let input = mode == .encryptor ? plaintext : ciphertext
            let expected = mode == .encryptor ? ciphertext : plaintext
            for split in 0...input.count {
                let cipher = try AESADNL(key: Array(key), iv: Array(iv), mode: mode)
                var output = try cipher.update(nonzeroSlice(Data(input.prefix(split))))
                XCTAssertEqual(output.count, split)
                output.append(try cipher.update(nonzeroSlice(Data(input.dropFirst(split)))))
                output.append(try cipher.updateFinish())
                XCTAssertEqual(output, expected, "Split at \(split)")
            }
        }
    }

    func testBytewiseUpdatesIncludingEmptyUpdates() throws {
        let cipher = try AESADNL(key: Array(key), iv: Array(iv), mode: .encryptor)
        var encrypted = Data()
        for byte in plaintext {
            XCTAssertEqual(try cipher.update(Data()), Data())
            encrypted.append(try cipher.update([byte]))
        }
        encrypted.append(try cipher.updateFinish())
        XCTAssertEqual(encrypted, ciphertext)
        let decryptor = try ADNLDecryptor(key: Array(key), iv: Array(iv))
        var decrypted = Data()
        for byte in encrypted { decrypted.append(try decryptor.update(Data([byte]))) }
        XCTAssertEqual(decrypted, plaintext)
    }

    func testNISTVectorsForOtherSupportedKeyLengths() throws {
        // NIST SP 800-38A, sections F.5.1 and F.5.3: first AES-128/192 block.
        let vectors = [
            ("2b7e151628aed2a6abf7158809cf4f3c", "874d6191b620e3261bef6864990db6ce"),
            ("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "1abc932417521ca24f2b0459fe7e6e0b")
        ]
        for (keyHex, ciphertextHex) in vectors {
            let key = Array(hex(keyHex))
            let expected = hex(ciphertextHex)
            let encryptor = try AESADNL(key: key, iv: Array(iv), mode: .encryptor)
            XCTAssertEqual(try encryptor.update(plaintext.prefix(16), isLast: true), expected)
            let decryptor = try AESADNL(key: key, iv: Array(iv), mode: .decryptor)
            XCTAssertEqual(try decryptor.update(expected, isLast: true), plaintext.prefix(16))
        }
    }

    func testInvalidKeyAndIVLengthsThrow() throws {
        for mode in [AESADNL.Mode.encryptor, .decryptor] {
            for count in [0, 1, 15, 17, 23, 25, 31, 33, 64] {
                XCTAssertThrowsError(try AESADNL(key: [UInt8](repeating: 0, count: count),
                                               iv: Array(iv), mode: mode))
            }
            for count in [0, 1, 12, 15, 17, 32] {
                XCTAssertThrowsError(try AESADNL(key: Array(key),
                                               iv: [UInt8](repeating: 0, count: count), mode: mode))
            }
        }
    }

    func testFinalizationPreservesPartialBlockState() throws {
        for mode in [AESADNL.Mode.encryptor, .decryptor] {
            let input = mode == .encryptor ? plaintext : ciphertext
            let expected = mode == .encryptor ? ciphertext : plaintext
            let cipher = try AESADNL(key: Array(key), iv: Array(iv), mode: mode)
            XCTAssertEqual(try cipher.updateFinish(), Data())
            var output = try cipher.update(nonzeroSlice(Data(input.prefix(17))), isLast: true)
            XCTAssertEqual(try cipher.updateFinish(), Data())
            XCTAssertEqual(try cipher.updateFinish(), Data())
            output.append(try cipher.update(Array(input.dropFirst(17)), isLast: true))
            XCTAssertEqual(try cipher.updateFinish(), Data())
            XCTAssertEqual(output, expected)
        }
    }

    func testCounterExhaustionThrowsWithoutConsumingRemainingBytes() throws {
        // Independent OpenSSL 3.5.4 AES-256-ECB encryption of the final counter block.
        let lastKeystream = hex("3b3c2921c85a24de9ac606ce6d1d60cc")
        for mode in [AESADNL.Mode.encryptor, .decryptor] {
            let zeros = Data(repeating: 0, count: 16)
            let input = mode == .encryptor ? zeros : lastKeystream
            let expected = mode == .encryptor ? lastKeystream : zeros
            let cipher = try AESADNL(key: Array(key), iv: [UInt8](repeating: 0xff, count: 16), mode: mode)
            XCTAssertThrowsError(try cipher.update(input + Data([0])))
            var output = try cipher.update(input.prefix(5))
            XCTAssertThrowsError(try cipher.update(input.dropFirst(5) + Data([0])))
            XCTAssertEqual(try cipher.updateFinish(), Data())
            output.append(try cipher.update(input.dropFirst(5), isLast: true))
            XCTAssertEqual(output, expected)
            XCTAssertEqual(try cipher.update(Data()), Data())
            XCTAssertThrowsError(try cipher.update([0]))
        }
    }
}
