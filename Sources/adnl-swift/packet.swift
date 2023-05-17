//
//  File.swift
//  
//
//  Created by Oleh Hudeichuk on 16.05.2023.
//

import Foundation
import Crypto
import SwiftExtensionsPack

/// size + nonce + hash
let PACKET_MIN_SIZE: Int = 4 + 32 + 32

public struct ADNLPacket {
    private let payload: Data
    private let nonce: Data
    
    public init(payload: Data, nonce: Data = .init(randomBytes(count: 32))) {
        self.payload = payload
        self.nonce = nonce
    }
    
    public init?(data: Data) throws {
        guard let obj: Self = try Self.parse(data: data) else { return nil }
        self.payload = obj.payload
        self.nonce = obj.nonce
    }
    
    public var hash: Data {
        get {
            var data: Data = .init()
            data.append(nonce)
            data.append(payload)
            return data.sha256()
        }
    }
    
    public var size: Data {
        get {
            Data(UInt32(payload.count + 32 + 32).toBytes(endian: .littleEndian))
        }
    }
    
    public var data: Data {
        get {
            var data: Data = .init()
            data.append(size)
            data.append(nonce)
            data.append(payload)
            data.append(hash)
            return data
        }
    }
    
    public var length: Int {
        get {
            PACKET_MIN_SIZE + payload.count
        }
    }
    
    private static func parse(data: Data) throws -> Self? {
        var cursor: Int = 0
        if data.count < 4 { return nil }
        let offset: Int = MemoryLayout<UInt32>.size
        cursor += offset
        let size: UInt32 = .init([UInt8](data[0..<offset]), endian: .littleEndian)
        if (data.count - offset) < Int(size) { return nil }
        let nonce: Data = data[offset..<offset + 32]
        cursor += 32
        let payload: Data = data[offset..<offset + (Int(size) - (32 + 32))]
        cursor += (Int(size) - (32 + 32))
        let hash: Data = data[offset..<offset + 32]
        cursor += 32
        var target: Data = .init()
        target.append(nonce)
        target.append(payload)
        target = target.sha256()
        
        if !(hash == target) {
            throw ADNLError("ADNLPacket: Bad packet hash.")
        }
        
        return .init(payload: payload, nonce: nonce)
    }
}
