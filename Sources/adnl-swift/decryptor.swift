//
//  File.swift
//  
//
//  Created by Oleh Hudeichuk on 27.05.2023.
//

import Foundation

public final class ADNLDecryptor {
    public let key: [UInt8]
    public let iv: [UInt8]
    public var cipher: AESADNL
    
    public init(key: [UInt8], iv: [UInt8]) throws {
        self.key = key
        self.iv = iv
        self.cipher = try AESADNL(key: key, iv: iv, mode: .decryptor)
    }
    
    public func update(_ data: Data) throws -> Data {
        try cipher.update(data)
    }
    
    public func adnlDeserializeMessage(data: Data) throws -> Data {
        let decryptedData: Data = try cipher.update(data)
        guard let packet: ADNLPacket = try .parse(data: decryptedData) else {
            throw ADNLError("Parse data error. Decrypted Data: \(decryptedData)")
        }
        return packet.payload
    }
}
