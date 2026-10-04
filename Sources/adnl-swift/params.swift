//
//  File.swift
//  
//
//  Created by Oleh Hudeichuk on 15.05.2023.
//

import Foundation
import SwiftExtensionsPack

public struct ADNLAESParams {
    public let bytes: [UInt8]
    private var _hash: Data?
    
    public init() {
        self.bytes = randomBytes(count: 160)
//        self.bytes = [
//            125, 162, 188,  61,  69,  99, 190, 246, 222, 182,
//             64,  22, 232, 158, 243, 238, 237, 194, 211, 250,
//            189, 155, 205,  95, 239, 250, 165, 111, 132,  24,
//            239,  56,  48, 159,  18, 186,  89,  81, 199, 230,
//            112,  37,  47, 214,  95, 202, 192,  89,  65,  20,
//            183, 206,  36, 165,  95, 214, 167,  97, 222,  74,
//            136, 119,  59, 106, 165,  17, 116,   3,  34, 180,
//            207,  65,  75, 118, 215, 131,   7,  96,  85, 108,
//            151, 178, 123, 137,  78,  17, 105,  43, 199, 228,
//            129, 126, 204, 151, 165, 225, 208, 133, 105,  61,
//            201, 183,  56,  31,  66,  65, 118, 164, 128,  64,
//            229, 188, 187, 135, 223, 189,  98, 234,  46, 208,
//            84, 222,  15,  62,  65,  63,  25, 122, 110,
//            35, 244,  47, 195,  21,   8, 252,   0, 185,
//            197, 137,   1, 199, 115, 138,  54,  71,  87,
//            241, 246,  55,  14, 123, 250, 208,  43,  92,
//            199, 209, 118, 123
//          ]
    }
    
    public init(_ data: Data) throws {
        if data.count != 160 { throw ADNLError("Data lenght must be 160 bytes, but data length is \(data.count)") }
        self.bytes = Array(data)
    }
    
    public init(_ data: String) throws {
        try self.init(data.dataFromHexOrBase64())
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
            _hash ?? Data(SEPCrypto.SHA.sha256.digest(data: Data(bytes)))
        }
    }
}
