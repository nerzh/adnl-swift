// swift-tools-version: 5.8

import PackageDescription

/// Rename this name + Root Folder + Target Folder inside Source
let name: String = "adnl-swift"

var packageDependencies: [Package.Dependency] = [
    .package(url: "https://github.com/apple/swift-crypto", .upToNextMajor(from: "2.5.0")),
    .package(url: "https://github.com/krzyzanowskim/CryptoSwift", .upToNextMajor(from: "1.7.1")),
    .package(url: "https://github.com/bitmark-inc/tweetnacl-swiftwrap", .upToNextMajor(from: "1.1.0")),
    .package(url: "https://github.com/apple/swift-nio-ssl", .upToNextMajor(from: "2.24.0")),
    .package(url: "https://github.com/bytehubio/BigInt", exact: "5.3.0"),
    .package(url: "https://github.com/christophhagen/CEd25519", branch: "master"),
]

var targetDependencies: [Target.Dependency] = [
    .product(name: "Crypto", package: "swift-crypto"),
    .product(name: "SwiftExtensionsPack", package: "swift-extensions-pack"),
    .product(name: "CryptoSwift", package: "CryptoSwift"),
    .product(name: "TweetNacl", package: "tweetnacl-swiftwrap"),
    .product(name: "BigInt", package: "BigInt"),
    .product(name: "NIOSSL", package: "swift-nio-ssl"),
    .product(name: "CEd25519", package: "CEd25519"),
]

#if os(Linux)
packageDependencies.append(.package(url: "https://github.com/nerzh/swift-extensions-pack", .upToNextMajor(from: "1.2.8")))
#else
packageDependencies.append(.package(path: "/Users/nerzh/mydata/swift_projects/swift-extensions-pack"))
#endif

let package = Package(
    name: name,
    platforms: [
        .macOS(.v12),
        .iOS(.v13),
    ],
    products: [
        .library(name: name, targets: [name])
    ],
    dependencies: packageDependencies,
    targets: [
        .target(
            name: name,
            dependencies: targetDependencies
        )
    ]
)
