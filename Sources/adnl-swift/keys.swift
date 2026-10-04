//
//  File.swift
//  
//
//  Created by Oleh Hudeichuk on 15.05.2023.
//

import Foundation
import SwiftExtensionsPack


public struct ADNLKeys {
    public typealias Keys = (publicKey: Data, sharedSecret: Data)
    public let peerPublic: Data
    public let `public`: Data
    public let sharedSecret: Data
    
    public init(privateKey: Data, peerPublicKey: Data) throws {
        try Ed25519Wrapper.validateKeyLength(privateKey, name: "Ed25519 private seed")
        try Ed25519Wrapper.validateKeyLength(peerPublicKey, name: "Ed25519 public key")
        self.peerPublic = Data(peerPublicKey)
        self.public = try Self.getPublicKey(privateKey: privateKey)
        self.sharedSecret = try Self.getSharedSecret(privateKey: privateKey, peer: peerPublicKey)
    }
    
    public init(privateKey: String, peerPublicKey: String) throws {
        try self.init(privateKey: privateKey.dataFromHexOrBase64(), peerPublicKey: peerPublicKey.dataFromHexOrBase64())
    }
    
    public init(peerPublicKey: Data) throws {
        let privateKey = randomData(count: 32)
        try self.init(privateKey: privateKey, peerPublicKey: peerPublicKey)
    }
    
    public init(peerPublicKey: String) throws {
        try self.init(peerPublicKey: try peerPublicKey.dataFromHexOrBase64())
    }
    
    private static func getPublicKey(privateKey: Data) throws -> Data {
        try Ed25519Wrapper.getPublicKey(privateKey: privateKey)
    }
    
    private static func getSharedSecret(privateKey: Data, peer: Data) throws -> Data {
        try Ed25519Wrapper.getSharedKey(privateKey: privateKey, publicKey: peer)
    }
}


/// asdf print
public func pe(_ line: Any...) {
    #if DEBUG
    let content: [Any] = ["asdf"] + line
    print(content.map{"\($0)"}.join(" "))
    #endif
}
