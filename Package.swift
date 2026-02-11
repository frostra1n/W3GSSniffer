// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "W3GSSniffer",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "W3GSSniffer", targets: ["W3GSSniffer"]),
    ],
    targets: [
        .systemLibrary(name: "CLibpcap", path: "Sources/CLibpcap"),
        .target(name: "W3GSSniffer", dependencies: ["CLibpcap"]),
        .testTarget(name: "W3GSSnifferTests", dependencies: ["W3GSSniffer"]),
    ]
)
