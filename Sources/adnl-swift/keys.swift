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
    public let peer: Data
    public let `public`: Data
    public let shared: Data
    
    public init(privateKey: Data, peerPublicKey: Data) throws {
        self.peer = peerPublicKey
        self.public = try Self.getPublicKey(privateKey: privateKey)
        self.shared = Self.getSharedSecret(privateKey: privateKey, peer: peerPublicKey)
    }
    
    public init(peerPublicKey: Data) throws {
        self.peer = peerPublicKey
        let privateKey: Data = .init(randomBytes(count: 32))
        self.public = try Self.getPublicKey(privateKey: privateKey)
        self.shared = Self.getSharedSecret(privateKey: privateKey, peer: peerPublicKey)
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
