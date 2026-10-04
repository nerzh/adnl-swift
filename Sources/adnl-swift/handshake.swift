//
//  File.swift
//  
//
//  Created by Oleh Hudeichuk on 27.05.2023.
//

import Foundation
import SwiftExtensionsPack

public final class ADNLHandshake {
    
    public static func adnlHandshake(keys: ADNLKeys, params: ADNLAESParams, address: ADNLAddress) throws -> Data {
        var key: Data = .init()
        key.append(keys.sharedSecret[0..<16])
        key.append(params.hash[16..<32])
        
        var nonce: Data = .init()
        nonce.append(params.hash[0..<4])
        nonce.append(keys.sharedSecret[20..<32])

        let cipher: AESADNL = try .init(key: Array(key), iv: Array(nonce), mode: .encryptor)
        var payload: Data = .init()
        try payload.append(cipher.update(params.bytes))
        var packet: Data = .init()
        packet.append(address.hash)
        packet.append(keys.public)
        packet.append(params.hash)
        packet.append(payload)
        
        return packet
    }
    
    public static func adnlParseHandshake(_ data: Data) throws -> HandshakeRequest {
        let handshakeLength: Int = 256
        if data.count != handshakeLength { throw ADNLError("HandshakeRequest must be \(handshakeLength) bytes, received \(data.count) bytes.") }
        let nodeId = Data(data.prefix(32))
        let pubKey = Data(data.dropFirst(32).prefix(32))
        let checkSum = Data(data.dropFirst(64).prefix(32))
        let encryptedData = Data(data.dropFirst(96))
        return HandshakeRequest(shortLocalNodeId: nodeId,
                                senderPubKey: pubKey,
                                checkSum: checkSum,
                                encryptedData: encryptedData)
    }
    
    public static func adnlHandshakeAssets(_ data: Data, secretKey: String) throws -> ADNLCipher {
        let request: HandshakeRequest = try adnlParseHandshake(data)
        let keys = try ADNLKeys(privateKey: secretKey, peerPublicKey: request.senderPubKey.toHexadecimal)
        if try ADNLAddress(publicKey: keys.public).hash != request.shortLocalNodeId {
            throw ADNLError("Handshake: ADNLAddress is not valid")
        }
        var key: Data = .init()
        key.append(keys.sharedSecret[0..<16])
        key.append(request.checkSum[16..<32])
        
        var nonce: Data = .init()
        nonce.append(request.checkSum[0..<4])
        nonce.append(keys.sharedSecret[20..<32])
        
        let decryptor: ADNLDecryptor = try .init(key: Array(key), iv: Array(nonce))
        let aesParamsData: Data = try decryptor.update(request.encryptedData)
        let params: ADNLAESParams = try .init(aesParamsData)
        if params.hash != request.checkSum {
            throw ADNLError("Handshake: ADNLAESParams is not valid")
        }
        
        return try .init(serverSecret: secretKey,
                         peerPubKey: request.senderPubKey.toHexadecimal,
                         paramsData: Data(params.bytes).toHexadecimal,
                         mode: .server)
    }
}

public extension ADNLHandshake {
    struct HandshakeRequest {
        public let shortLocalNodeId: Data
        public let senderPubKey: Data
        public let checkSum: Data
        public let encryptedData: Data
    }
}
