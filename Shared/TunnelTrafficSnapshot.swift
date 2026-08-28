import Foundation

struct TunnelTrafficSnapshot: Codable, Equatable, Sendable {
    let sentBytes: Int64
    let receivedBytes: Int64

    static let zero = TunnelTrafficSnapshot(sentBytes: 0, receivedBytes: 0)
}

enum TunnelProviderMessage {
    // A fixed binary request avoids placing profile identifiers or configuration
    // material in the provider-message channel.
    static let trafficSnapshotRequest = Data("tunnel-traffic-v1".utf8)
}
