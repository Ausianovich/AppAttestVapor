// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "Server",
    platforms: [.macOS(.v26)],
    dependencies: [
        .package(path: "../AppAttestVapor"),
        .package(
            url: "https://github.com/vapor/vapor.git",
            from: "4.121.4"
        ),
        .package(
            url: "https://github.com/vapor/fluent.git",
            from: "4.0.0"
        ),
        .package(
            url: "https://github.com/vapor/fluent-postgres-driver.git",
            from: "2.12.0"
        ),
        .package(
            url: "https://github.com/vapor/sql-kit.git",
            from: "3.0.0"
        ),
        .package(
            url: "https://github.com/pointfreeco/swift-dependencies",
            from: "1.14.1"
        ),
        .package(
            url: "https://github.com/vapor-community/valkey.git",
            from: "1.2.0"
        ),
        .package(
            url: "https://github.com/valkey-io/valkey-swift.git",
            from: "1.0.0"
        ),
    ],
    targets: [
        .executableTarget(
            name: "App",
            dependencies: [
                .product(
                    name: "AppAttestVapor",
                    package: "appattestvapor"
                ),
                .product(
                    name: "Dependencies",
                    package: "swift-dependencies"
                ),
                .product(name: "Fluent", package: "fluent"),
                .product(
                    name: "FluentPostgresDriver",
                    package: "fluent-postgres-driver"
                ),
                .product(name: "SQLKit", package: "sql-kit"),
                .product(name: "Valkey", package: "valkey-swift"),
                .product(name: "Vapor", package: "vapor"),
                .product(name: "VaporValkey", package: "valkey"),
            ]
        ),
    ]
)
