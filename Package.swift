// swift-tools-version: 6.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "AppAttestVapor",
    products: [
        .library(
            name: "AppAttestVapor",
            targets: ["AppAttestVapor"]
        ),
        .library(
            name: "AppAttestDevice",
            targets: ["AppAttestDevice"]
        ),
    ],
    dependencies: [
        .package(
            url: "https://github.com/pointfreeco/swift-dependencies",
            from: "1.14.1"
        ),
    ],
    targets: [
        .target(
            name: "AppAttestVapor",
            dependencies: [
                .product(
                    name: "Dependencies",
                    package: "swift-dependencies"
                ),
            ]
        ),
        .target(
            name: "AppAttestDevice",
            dependencies: [
                .product(
                    name: "Dependencies",
                    package: "swift-dependencies"
                ),
            ]
        ),
        .testTarget(
            name: "AppAttestVaporTests",
            dependencies: ["AppAttestVapor"]
        ),
        .testTarget(
            name: "AppAttestDeviceTests",
            dependencies: ["AppAttestDevice"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
