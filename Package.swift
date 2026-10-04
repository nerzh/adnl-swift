// swift-tools-version: 6.2

import PackageDescription

let name: String = "adnl-swift"

var packageDependencies: [Package.Dependency] = [
    .package(url: "https://github.com/nerzh/swift-extensions-pack", exact: "2.9.0"),
]

var targetDependencies: [Target.Dependency] = [
    .product(name: "SwiftExtensionsPack", package: "swift-extensions-pack"),
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
        .testTarget(name: "ADNLTests", dependencies: ["adnl-swift"])
    ],
    swiftLanguageModes: [.v5]
)
