// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "GatewayShield",
    // Only the platforms CI actually builds. Linux is implied (CI builds and tests the core there).
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "GatewayShield", targets: ["GatewayShield"]),
        .library(name: "GatewayShieldUI", targets: ["GatewayShieldUI"]),
    ],
    targets: [
        .target(name: "GatewayShield"),
        .target(name: "GatewayShieldUI", dependencies: ["GatewayShield"]),
        .testTarget(name: "GatewayShieldTests", dependencies: ["GatewayShield"]),
    ]
)
