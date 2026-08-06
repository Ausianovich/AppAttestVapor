// swift-tools-version: 6.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "AppAttestVapor",
    platforms: [
        .iOS(.v26),
        .macOS(.v26),
    ],
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
        .package(
            url: "https://github.com/vapor/vapor.git",
            from: "4.121.4"
        ),
        .package(
            url: "https://github.com/vapor-community/valkey.git",
            from: "1.2.0"
        ),
        .package(
            url: "https://github.com/apple/swift-openapi-runtime.git",
            from: "1.12.0"
        ),
        .package(
            url: "https://github.com/apple/swift-crypto.git",
            from: "4.5.1"
        ),
        .package(
            url: "https://github.com/apple/swift-certificates.git",
            from: "1.19.4"
        ),
        .package(
            url: "https://github.com/valpackett/SwiftCBOR.git",
            "0.6.0"..<"0.7.0"
        ),
        .package(
            url: "git@github.com:Ausianovich/KeyChain.git",
            from: "2.0.0"
        ),
    ],
    targets: [
        .target(
            name: "AppAttestCore",
            dependencies: [
                .product(
                    name: "Crypto",
                    package: "swift-crypto"
                ),
            ]
        ),
        .target(
            name: "AppAttestVapor",
            dependencies: [
                "AppAttestCore",
                .product(
                    name: "Dependencies",
                    package: "swift-dependencies"
                ),
                .product(
                    name: "Crypto",
                    package: "swift-crypto"
                ),
                .product(
                    name: "SwiftCBOR",
                    package: "SwiftCBOR"
                ),
                .product(
                    name: "Vapor",
                    package: "vapor"
                ),
                .product(
                    name: "VaporValkey",
                    package: "valkey"
                ),
                .product(
                    name: "X509",
                    package: "swift-certificates"
                ),
            ],
            resources: [.process("Resources")]
        ),
        .target(
            name: "AppAttestDevice",
            dependencies: [
                "AppAttestCore",
                .product(
                    name: "Dependencies",
                    package: "swift-dependencies"
                ),
                .product(
                    name: "KeyChain",
                    package: "KeyChain"
                ),
                .product(
                    name: "OpenAPIRuntime",
                    package: "swift-openapi-runtime"
                ),
            ]
        ),
        .testTarget(
            name: "AppAttestVaporTests",
            dependencies: [
                "AppAttestVapor",
                .product(
                    name: "Crypto",
                    package: "swift-crypto"
                ),
                .product(
                    name: "DependenciesTestSupport",
                    package: "swift-dependencies"
                ),
                .product(
                    name: "VaporTesting",
                    package: "vapor"
                ),
                .product(
                    name: "X509",
                    package: "swift-certificates"
                ),
            ],
            resources: [.copy("Fixtures")]
        ),
        .testTarget(
            name: "AppAttestDeviceTests",
            dependencies: [
                "AppAttestDevice",
                .product(
                    name: "DependenciesTestSupport",
                    package: "swift-dependencies"
                ),
            ]
        ),
        .testTarget(
            name: "AppAttestCoreTests",
            dependencies: ["AppAttestCore"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
