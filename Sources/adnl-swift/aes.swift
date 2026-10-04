//
//  File.swift
//  
//
//  Created by Oleh Hudeichuk on 17.05.2023.
//

import Foundation
import SwiftExtensionsPack

public final class AESADNL {
    public let key: [UInt8]
    public let iv: [UInt8]
    public var cipher: SEPCrypto.AESCTR
    
    public init(key: [UInt8], iv: [UInt8], mode: Mode) throws {
        self.key = key
        self.iv = iv
        // CTR uses the same operation for encryption and decryption.
        self.cipher = try SEPCrypto.AESCTR(key: Data(key), iv: Data(iv))
    }
    
    public func update(_ bytes: Array<UInt8>, isLast: Bool = false) throws -> Data {
        try update(Data(bytes), isLast: isLast)
    }
    
    public func update(_ data: Data, isLast: Bool = false) throws -> Data {
        // CTR has no padding or final block; isLast is retained for compatibility.
        try cipher.update(data: data)
    }
    
    public func updateFinish() throws -> Data {
        // Every update emits all input bytes, so there is nothing to flush.
        Data()
    }
}

public extension AESADNL {
    enum Mode {
        case encryptor
        case decryptor
    }
}
