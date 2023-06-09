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
//        let privateKey = Data([
//            246, 116, 7, 178, 228, 48, 202, 58,
//            176, 18, 214, 185, 242, 220, 1, 6,
//            114, 141, 225, 45, 165, 209, 92, 249,
//            208, 98, 94, 132, 233, 224, 172, 103
//        ])
        self.peerPublic = peerPublicKey
        self.public = try Self.getPublicKey(privateKey: privateKey)
        self.sharedSecret = Self.getSharedSecret(privateKey: privateKey, peer: peerPublicKey)
//        
//        pe("ADNLKeys - public", self.public.toHexadecimal)
//        pe("ADNLKeys - peerPublic", self.peerPublic.toHexadecimal)
//        pe("ADNLKeys - sharedSecret", sharedSecret.toHexadecimal)
    }
    
    public init(privateKey: String, peerPublicKey: String) throws {
        try self.init(privateKey: privateKey.dataFromHexOrBase64(), peerPublicKey: peerPublicKey.dataFromHexOrBase64())
    }
    
    public init(peerPublicKey: Data) throws {
        let privateKey: Data = .init(randomBytes(count: 32))
        try self.init(privateKey: privateKey, peerPublicKey: peerPublicKey)
    }
    
    public init(peerPublicKey: String) throws {
        try self.init(peerPublicKey: try peerPublicKey.dataFromHexOrBase64())
    }
    
    private static func getPublicKey(privateKey: Data) throws -> Data {
        try Ed25519Wrapper.getPublicKey(privateKey: privateKey)
    }
    
    private static func getSharedSecret(privateKey: Data, peer: Data) -> Data {
        Ed25519Wrapper.getSharedKey(privateKey: privateKey, publicKey: peer)
    }
}


/// asdf print
public func pe(_ line: Any...) {
    #if DEBUG
    let content: [Any] = ["asdf"] + line
    print(content.map{"\($0)"}.join(" "))
    #endif
}
