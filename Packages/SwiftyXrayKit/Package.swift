// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "SwiftyXrayKit",
    platforms: [.iOS(.v16)],
    products: [
        .library(name: "SwiftyXrayKit", targets: ["SwiftyXrayKit"]),
    ],
    targets: [
        .target(name: "SystemDNS", path: "Sources/SystemDNS", linkerSettings: [.linkedLibrary("resolv")]),
        .binaryTarget(
            name: "LibXray",
            path: "Frameworks/LibXray.xcframework"
        ),
        .target(
            name: "SwiftyXrayKit",
            dependencies: ["LibXray", "SystemDNS"],
            path: "Sources/SwiftyXrayKit",
            linkerSettings: [.linkedLibrary("resolv")]
        ),
    ]
)
