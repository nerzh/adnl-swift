//
//  File.swift
//  
//
//  Created by Oleh Hudeichuk on 15.05.2023.
//

import Foundation
import SwiftExtensionsPack

public struct ADNLError: ErrorCommon, Encodable {
    public var title: String = "ADNL Error"
    public var reason: String = ""
    public init() {}
}
