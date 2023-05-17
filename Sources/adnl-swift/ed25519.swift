//
//  File.swift
//  
//
//  Created by Oleh Hudeichuk on 16.05.2023.
//

import Foundation
import CEd25519
import Crypto

open class Ed25519Wrapper {
    
    public class func edwardsToMontgomery(bytesData: Data) -> Data {
        var bytesData: Data = bytesData
        var y_coordinate: UInt8 = bytesData[31] & 0x7F
        if (bytesData[31] & 0x80) != 0 {
            y_coordinate += 0x80
        }
        bytesData.append(y_coordinate)
        
        return bytesData
    }
    
    public class func convertEd25519ToX25519(ed25519PrivateKey: Data) -> Data {
        var sha512Hash: Data = Data(ed25519PrivateKey).sha512()
        
        sha512Hash[0] &= 248
        sha512Hash[31] &= 127
        sha512Hash[31] |= 64
        
        return sha512Hash[0...31]
    }
    
    public class func getPublicKey(privateKey: Data) throws -> Data {
        let privateKey: Curve25519.Signing.PrivateKey = try .init(rawRepresentation: privateKey)
        return privateKey.publicKey.rawRepresentation
    }
    
    public class func getSharedKey(privateKey: Data, publicKey: Data) -> Data {
        let bytesCount: Int = 32
        var privateKey: [UInt8] = .init(convertEd25519ToX25519(ed25519PrivateKey: privateKey))
        var publicKey: [UInt8] = .init(edwardsToMontgomery(bytesData: publicKey))

        let buffer: UnsafeMutablePointer<UInt8> = .allocate(capacity: bytesCount)
        buffer.initialize(repeating: 0, count: bytesCount)
        defer {
            buffer.deinitialize(count: bytesCount)
            buffer.deallocate()
        }
        let bufferPointer: UnsafeBufferPointer = .init(start: buffer, count: bytesCount)
        ed25519_key_exchange(buffer, &publicKey, &privateKey)
        
        return .init(bufferPointer)
    }
}
