import Foundation

enum XrayConfigHardener {
    static let directBootstrapAddresses = ["1.1.1.1", "9.9.9.9"]

    private static let realityServerOnlyKeys: Set<String> = [
        "masterKeyLog",
        "show",
        "target",
        "dest",
        "type",
        "xver",
        "serverNames",
        "privateKey",
        "minClientVer",
        "maxClientVer",
        "maxTimeDiff",
        "shortIds",
        "mldsa65Seed",
        "limitFallbackUpload",
        "limitFallbackDownload"
    ]

    static func harden(_ source: [String: Any]) throws -> [String: Any] {
        guard var outbounds = source["outbounds"] as? [[String: Any]], !outbounds.isEmpty else {
            throw ClientError.unsupportedConfiguration
        }

        var config = source
        config.removeValue(forKey: "api")
        config.removeValue(forKey: "reverse")
        config["log"] = ["loglevel": "warning", "dnsLog": false]

        // A subscription must not choose the device's local source address.
        // This also removes a value emitted by the bundled share-link converter,
        // which currently puts the human-readable profile name in `sendThrough`.
        // Xray expects an IP address there and otherwise rejects the configuration
        // before the tunnel can start.
        outbounds = outbounds.map { outbound in
            var sanitized = outbound
            sanitized.removeValue(forKey: "sendThrough")
            if var streamSettings = sanitized["streamSettings"] as? [String: Any],
               var realitySettings = streamSettings["realitySettings"] as? [String: Any] {
                realityServerOnlyKeys.forEach { realitySettings.removeValue(forKey: $0) }
                streamSettings["realitySettings"] = realitySettings
                sanitized["streamSettings"] = streamSettings
            }
            return sanitized
        }

        if !outbounds.contains(where: { ($0["tag"] as? String) == "dns-out" }) {
            outbounds.append(["protocol": "dns", "tag": "dns-out"])
        }
        config["outbounds"] = outbounds

        if config["dns"] == nil {
            config["dns"] = [
                "queryStrategy": "UseIPv4",
                "servers": [
                    ["address": "https+local://\(directBootstrapAddresses[0])/dns-query", "tag": "dns-bootstrap-cloudflare"],
                    ["address": "https+local://\(directBootstrapAddresses[1])/dns-query", "tag": "dns-bootstrap-quad9"]
                ]
            ]
        }

        var routing = config["routing"] as? [String: Any] ?? [:]
        var rules = routing["rules"] as? [[String: Any]] ?? []
        if !rules.contains(where: { ($0["port"] as? Int) == 53 || ($0["port"] as? String) == "53" }) {
            rules.insert([
                "type": "field",
                "network": "tcp,udp",
                "port": 53,
                "outboundTag": "dns-out",
                "ruleTag": "client-dns-intercept"
            ], at: 0)
        }
        routing["rules"] = rules
        routing["domainMatcher"] = routing["domainMatcher"] ?? "hybrid"
        config["routing"] = routing
        return config
    }
}
