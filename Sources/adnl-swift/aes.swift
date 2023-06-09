//
//  File.swift
//  
//
//  Created by Oleh Hudeichuk on 17.05.2023.
//

import Foundation
import CryptoSwift
import SwiftExtensionsPack

public final class AESADNL {
    public let key: [UInt8]
    public let iv: [UInt8]
    public var cipher: (Cryptor & Updatable)
    
    public init(key: [UInt8], iv: [UInt8], mode: Mode) throws {
        self.key = key
        self.iv = iv
        let tempCipher = try AES(key: key, blockMode: CTR(iv: iv), padding: .noPadding)
        switch mode {
        case .encryptor:
            self.cipher = try tempCipher.makeEncryptor()
        case .decryptor:
            self.cipher = try tempCipher.makeDecryptor()
        }
    }
    
    public func update(_ bytes: Array<UInt8>, isLast: Bool = false) throws -> Data {
        try .init(cipher.update(withBytes: bytes, isLast: isLast))
    }
    
    public func update(_ data: Data, isLast: Bool = false) throws -> Data {
        try .init(cipher.update(withBytes: data.bytes, isLast: isLast))
    }
    
    public func updateFinish() throws -> Data {
        try .init(cipher.finish())
    }
}

public extension AESADNL {
    enum Mode {
        case encryptor
        case decryptor
    }
}
