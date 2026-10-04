// swift-tools-version: 6.2

import PackageDescription

let name: String = "adnl-swift"

var packageDependencies: [Package.Dependency] = [
    .package(url: "https://github.com/nerzh/swift-extensions-pack", from: "2.10.0"),
    .package(url: "https://github.com/apple/swift-nio.git", from: "2.98.0"),
]

var targetDependencies: [Target.Dependency] = [
    .product(name: "SwiftExtensionsPack", package: "swift-extensions-pack"),
    .product(name: "NIOCore", package: "swift-nio"),
    .product(name: "NIOPosix", package: "swift-nio"),
]

let package = Package(
    name: name,
    platforms: [
        .macOS(.v11),
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
        ),
        .testTarget(name: "ADNLTests", dependencies: [
            "adnl-swift",
            .product(name: "NIOCore", package: "swift-nio"),
            .product(name: "NIOPosix", package: "swift-nio"),
            .product(name: "NIOEmbedded", package: "swift-nio"),
        ])
    ],
    swiftLanguageModes: [.v5]
)
