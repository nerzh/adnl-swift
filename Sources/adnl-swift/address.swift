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
    
    public init(publicKey: [UInt8]) {
        self.publicKey = Data(publicKey)
    }
    
    public init(publicKey: String) throws {
        if publicKey.isHexNumber {
            self.publicKey = try publicKey.remove0x.dataFromHexThrowing()
        } else if publicKey.isBase64() {
            self.publicKey = Data(base64Encoded: publicKey)!
        } else {
            throw ADNLError.mess("\(publicKey) undefined publicKey format")
        }
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
