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
    public let payload: Data
    public let nonce: Data
    
    public init(payload: Data, nonce: Data = .init(randomBytes(count: 32))) {
        self.payload = payload
        self.nonce = nonce
//        self.nonce = Data([251, 90, 41, 69, 167, 63, 2, 148, 174, 239, 72, 100, 90, 84, 194, 163, 1, 154, 201, 9, 213, 80, 241, 33, 232, 241, 233, 68, 225, 45, 0, 8])
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
    
    public static func parse(data: Data) throws -> Self? {
        var cursor: Int = 0
        if data.count < 4 { return nil }
        let offset: Int = MemoryLayout<UInt32>.size
        cursor += offset
        let size: UInt32 = .init([UInt8](data[0..<cursor]), endian: .littleEndian)
        if (data.count - cursor) < Int(size) { return nil }
        let nonce: Data = data[cursor..<(cursor + 32)]
        cursor += 32
        let payload: Data = data[cursor..<(cursor + (Int(size) - (32 + 32)))]
        cursor += (Int(size) - (32 + 32))
        let hash: Data = data[cursor..<(cursor + 32)]
        cursor += 32
        var target: Data = .init()
        target.append(nonce)
        target.append(payload)
        target = target.sha256()
        
        if hash != target {
            throw ADNLError("ADNLPacket: Bad packet hash.")
        }
        
        /// Init new Data(...) because after gets by range indexes of bytes is not overridden
        return .init(payload: Data(payload), nonce: Data(nonce))
    }
}
