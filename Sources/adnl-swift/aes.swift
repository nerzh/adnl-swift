//
//  File.swift
//  
//
//  Created by Oleh Hudeichuk on 17.05.2023.
//

import Foundation
import CryptoSwift

public final class AESADNL {
    let key: [UInt8]
    let iv: [UInt8]
    let cipher: AES
    
    init(key: [UInt8], iv: [UInt8]) throws {
        self.key = key
        self.iv = iv
        self.cipher = try AES(key: key, blockMode: CTR(iv: iv), padding: .noPadding)
    }
    
    func encrypt(_ data: Array<UInt8>) throws -> Data {
        try .init(cipher.encrypt(data))
    }
    
    func decrypt(_ data: Array<UInt8>) throws -> Data {
        try .init(cipher.decrypt(data))
    }
    
    func adnlHandshake(keys: ADNLKeys, params: ADNLAESParams, address: ADNLAddress) throws -> Data {
        var key: Data = .init()
        key.append(keys.shared[0..<16])
        key.append(params.hash[16..<32])
        
        var nonce: Data = .init()
        nonce.append(params.hash[0..<4])
        nonce.append(keys.shared[20..<32])
        
        let cipher: Self = try .init(key: key.bytes, iv: nonce.bytes)
        var payload: Data = .init()
        try payload.append(cipher.encrypt(params.bytes))
        
        var packet: Data = .init()
        packet.append(address.hash)
        packet.append(keys.public)
        packet.append(params.hash)
        packet.append(payload)
        
        return packet
    }
}
