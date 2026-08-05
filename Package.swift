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
    targets: [
        .target(
            name: "AppAttestVapor"
        ),
        .target(
            name: "AppAttestDevice"
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
