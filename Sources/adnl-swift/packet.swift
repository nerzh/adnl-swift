//
//  File.swift
//  
//
//  Created by Oleh Hudeichuk on 16.05.2023.
//

import Foundation
import SwiftExtensionsPack

/// size + nonce + hash
let PACKET_MIN_SIZE: Int = 4 + 32 + 32

public struct ADNLPacket {
    public let payload: Data
    public let nonce: Data
    
    public init(payload: Data) {
        self.payload = payload
        self.nonce = randomData(count: 32)
    }

    public init(payload: Data, nonce: Data) throws {
        guard nonce.count == 32 else {
            throw ADNLError("ADNLPacket nonce must be exactly 32 bytes, received \(nonce.count).")
        }
        self.payload = payload
        self.nonce = Data(nonce)
    }
    
    public var hash: Data {
        get {
            var data: Data = .init()
            data.append(nonce)
            data.append(payload)
            return Data(SEPCrypto.SHA.sha256.digest(data: data))
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
        if data.count < 4 { return nil }
        // Decode without assuming alignment, native byte order, or a zero startIndex.
        let size = data.prefix(4).enumerated().reduce(UInt32(0)) {
            $0 | (UInt32($1.element) << ($1.offset * 8))
        }
        guard size >= 64 else {
            throw ADNLError("ADNLPacket body must be at least 64 bytes, received \(size).")
        }
        guard UInt64(data.count - 4) >= UInt64(size) else { return nil }
        let body = data.dropFirst(4).prefix(Int(size))
        let nonce = body.prefix(32)
        let payload = body.dropFirst(32).dropLast(32)
        let hash = body.suffix(32)
        let target = Data(SEPCrypto.SHA.sha256.digest(data: Data(body.dropLast(32))))
        if hash != target {
            throw ADNLError("ADNLPacket: Bad packet hash.")
        }
        
        return try .init(payload: Data(payload), nonce: Data(nonce))
    }
}
