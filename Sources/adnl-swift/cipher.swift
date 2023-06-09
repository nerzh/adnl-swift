//
//  File.swift
//  
//
//  Created by Oleh Hudeichuk on 29.05.2023.
//

import Foundation

public struct ADNLCipher {
    public let keys: ADNLKeys
    public let params: ADNLAESParams
    public let address: ADNLAddress
    public let encryptor: ADNLEncryptor
    public let decryptor: ADNLDecryptor
    
    public init(serverSecret: String, peerPubKey: String, paramsData: String, mode: TCPCipherMode) throws {
        self.keys = try ADNLKeys(privateKey: serverSecret, peerPublicKey: peerPubKey)
        self.params = try ADNLAESParams(paramsData)
        self.address = try ADNLAddress(publicKey: peerPubKey)
        let cipherPair: (encryptor: ADNLEncryptor, decryptor: ADNLDecryptor) = try Self.makePair(mode: mode, params: self.params)
        self.encryptor = cipherPair.encryptor
        self.decryptor = cipherPair.decryptor
    }
    
    public init(serverSecret: String, peerPubKey: String, mode: TCPCipherMode) throws {
        self.keys = try ADNLKeys(privateKey: serverSecret, peerPublicKey: peerPubKey)
        self.params = ADNLAESParams()
        self.address = try ADNLAddress(publicKey: peerPubKey)
        let cipherPair: (encryptor: ADNLEncryptor, decryptor: ADNLDecryptor) = try Self.makePair(mode: mode, params: self.params)
        self.encryptor = cipherPair.encryptor
        self.decryptor = cipherPair.decryptor
    }
    
    public init(peerPubKey: String, mode: TCPCipherMode) throws {
        self.keys = try ADNLKeys(peerPublicKey: peerPubKey)
        self.params = ADNLAESParams()
        self.address = try ADNLAddress(publicKey: peerPubKey)
        let cipherPair: (encryptor: ADNLEncryptor, decryptor: ADNLDecryptor) = try Self.makePair(mode: mode, params: self.params)
        self.encryptor = cipherPair.encryptor
        self.decryptor = cipherPair.decryptor
    }
    
    private static func makePair(mode: TCPCipherMode, params: ADNLAESParams) throws -> (encryptor: ADNLEncryptor, decryptor: ADNLDecryptor) {
        var encryptor: ADNLEncryptor!
        var decryptor: ADNLDecryptor!
        
        switch mode {
        case .client:
            encryptor = try .init(key: params.txKey, iv: params.txNonce)
            decryptor = try .init(key: params.rxKey, iv: params.rxNonce)
        case .server:
            encryptor = try .init(key: params.rxKey, iv: params.rxNonce)
            decryptor = try .init(key: params.txKey, iv: params.txNonce)
        }
        return (encryptor: encryptor, decryptor: decryptor)
    }
}

public extension ADNLCipher {
    enum TCPCipherMode {
        case client
        case server
    }
}

