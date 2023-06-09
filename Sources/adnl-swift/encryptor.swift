//
//  File.swift
//  
//
//  Created by Oleh Hudeichuk on 27.05.2023.
//

import Foundation

public final class ADNLEncryptor {
    public let key: [UInt8]
    public let iv: [UInt8]
    public var cipher: AESADNL
    
    public init(key: [UInt8], iv: [UInt8]) throws {
        self.key = key
        self.iv = iv
        self.cipher = try AESADNL(key: key, iv: iv, mode: .encryptor)
    }
    
    public func update(_ data: Data) throws -> Data {
        try cipher.update(data)
    }
    
    public func adnlSerializeMessage(data: Data) throws -> Data {
        let packet: ADNLPacket = .init(payload: data)
        return try cipher.update(packet.data)
    }
}
