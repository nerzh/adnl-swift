//
//  File.swift
//  
//
//  Created by Oleh Hudeichuk on 16.05.2023.
//

import Foundation
import SwiftExtensionsPack

open class Ed25519Wrapper {
    
    /// Converts an encoded Edwards y-coordinate to a 32-byte, little-endian Montgomery u-coordinate.
    /// This coordinate mapping does not validate curve membership or subgroup order.
    /// Do not pass its result to getSharedKey, which accepts an Edwards public key.
    public class func edwardsToMontgomery(bytesData: Data) throws -> Data {
        try validateKeyLength(bytesData, name: "Ed25519 public key")
        do {
            return try SEPCrypto.Ed25519.edwardsToMontgomery(bytesData: bytesData)
        } catch {
            throw ADNLError(error.localizedDescription)
        }
    }
    
    /// Derives a 32-byte X25519 scalar from a 32-byte Ed25519 seed, not an expanded secret key.
    public class func convertEd25519ToX25519(ed25519PrivateKey: Data) throws -> Data {
        try validateKeyLength(ed25519PrivateKey, name: "Ed25519 private seed")
        return SEPCrypto.Ed25519.convertEd25519ToX25519(ed25519PrivateKey: Data(ed25519PrivateKey))
    }
    
    public class func getPublicKey(privateKey: Data) throws -> Data {
        try validateKeyLength(privateKey, name: "Ed25519 private seed")
        return SEPCrypto.Ed25519.createKeyPair(seed32Byte: Data(privateKey)).public
    }
    
    /// Computes the ADNL shared secret from a 32-byte Ed25519 seed and a 32-byte Edwards public key.
    public class func getSharedKey(privateKey: Data, publicKey: Data) throws -> Data {
        try validateKeyLength(privateKey, name: "Ed25519 private seed")
        try validateKeyLength(publicKey, name: "Ed25519 public key")
        let scalar = try convertEd25519ToX25519(ed25519PrivateKey: privateKey)
        // ed25519_key_exchange performs the Edwards-to-Montgomery conversion internally.
        do {
            return try SEPCrypto.Ed25519.getKeyExchange(privateKey: scalar, publicKey: publicKey)
        } catch {
            throw ADNLError(error.localizedDescription)
        }
    }

    internal static func validateKeyLength(_ key: Data, name: String) throws {
        guard key.count == 32 else {
            throw ADNLError("\(name) must be exactly 32 bytes, received \(key.count).")
        }
    }
}
