import Foundation

struct LocalSocksCredentials: Equatable, Sendable {
    let port: Int
    let username: String
    let password: String
}

enum XraySocksInboundBuilder {
    static func replacingInbounds(
        in source: [String: Any],
        credentials: LocalSocksCredentials
    ) throws -> [String: Any] {
        guard (1...65_535).contains(credentials.port),
              !credentials.username.isEmpty,
              !credentials.password.isEmpty else {
            throw ClientError.unsupportedConfiguration
        }

        var config = source
        config["inbounds"] = [[
            "listen": "127.0.0.1",
            "port": credentials.port,
            "protocol": "socks",
            "settings": [
                "auth": "password",
                "accounts": [[
                    "user": credentials.username,
                    "pass": credentials.password
                ]],
                "ip": "127.0.0.1",
                "udp": true
            ],
            "sniffing": [
                "destOverride": ["http", "tls", "quic"],
                "enabled": true,
                "routeOnly": false,
                "metadataOnly": false,
                "domainsExcluded": []
            ],
            // Preserve the tag emitted by the converter so imported routing
            // rules that explicitly select the generated inbound keep working.
            "tag": "in_proxy"
        ]]
        return config
    }
}
