//
//  File.swift
//  
//
//  Created by Oleh Hudeichuk on 14.05.2023.
//

import Foundation
import SwiftExtensionsPack
import CryptoSwift

public struct ADNLAddress {
    public let publicKey: Data
    private var _hash: Data?
    
    public init(publicKey: Data) {
        self.publicKey = Data(publicKey)
    }
    
    public init(publicKey: [UInt8]) {
        self.init(publicKey: Data(publicKey))
    }
    
    public init(publicKey: String) throws {
        self.init(publicKey: try publicKey.dataFromHexOrBase64())
    }
    
    public var hash: Data {
        get {
            _hash ?? {
                let typeEd25519: [UInt8] = [ 0xc6, 0xb4, 0x13, 0x48 ]
                var data = Data(typeEd25519)
                data.append(publicKey)
                return data.sha256()
            }()
        }
    }
}
