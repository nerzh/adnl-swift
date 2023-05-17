//
//  File.swift
//  
//
//  Created by Oleh Hudeichuk on 15.05.2023.
//

import Foundation
import SwiftExtensionsPack
import CryptoSwift

public struct ADNLAESParams {
    public let bytes: [UInt8]
    private var _hash: Data?
    
    public init() {
        self.bytes = randomBytes(count: 160)
    }
    
    public var rxKey: [UInt8] {
        Array<UInt8>(bytes[0..<32])
    }
    
    public var txKey: [UInt8] {
        Array<UInt8>(bytes[32..<64])
    }
    
    public var rxNonce: [UInt8] {
        Array<UInt8>(bytes[64..<80])
    }
    
    public var txNonce: [UInt8] {
        Array<UInt8>(bytes[80..<96])
    }
    
    public var padding: [UInt8] {
        Array<UInt8>(bytes[96..<160])
    }
    
    public var hash: Data {
        get {
            _hash ?? Data(bytes).sha256()
        }
    }
}
