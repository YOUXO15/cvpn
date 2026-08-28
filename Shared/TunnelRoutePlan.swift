import Darwin
import Foundation

struct TunnelIPAddress: Hashable, Sendable {
    enum Family: Hashable, Sendable {
        case ipv4
        case ipv6
    }

    let value: String
    let family: Family
}

enum XrayOutboundEndpointExtractor {
    private static let supportedProtocols: Set<String> = [
        "shadowsocks", "socks", "trojan", "vless", "vmess"
    ]

    static func hosts(in config: [String: Any]) -> [String] {
        guard let outbounds = config["outbounds"] as? [Any] else { return [] }
        var seen = Set<String>()
        var result: [String] = []

        for item in outbounds {
            guard let outbound = dictionary(item) else { continue }
            guard let protocolName = outbound["protocol"] as? String,
                  supportedProtocols.contains(protocolName.lowercased()),
                  let settings = dictionary(outbound["settings"]) else {
                continue
            }
            for collectionName in ["servers", "vnext"] {
                guard let endpoints = settings[collectionName] as? [Any] else { continue }
                for item in endpoints {
                    guard let endpoint = dictionary(item) else { continue }
                    guard let rawAddress = endpoint["address"] as? String else { continue }
                    let address = normalize(rawAddress)
                    guard !address.isEmpty, seen.insert(address).inserted else { continue }
                    result.append(address)
                }
            }
        }
        return result
    }

    private static func dictionary(_ value: Any?) -> [String: Any]? {
        if let dictionary = value as? [String: Any] {
            return dictionary
        }
        guard let dictionary = value as? NSDictionary else { return nil }
        var result: [String: Any] = [:]
        for (key, value) in dictionary {
            guard let key = key as? String else { continue }
            result[key] = value
        }
        return result
    }

    private static func normalize(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("["), trimmed.hasSuffix("]"), trimmed.count > 2 {
            return String(trimmed.dropFirst().dropLast())
        }
        return trimmed
    }
}

enum ShareLinkEndpointExtractor {
    private static let directHostSchemes: Set<String> = ["trojan", "vless"]

    static func host(in link: String) -> String? {
        let trimmed = link.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let components = URLComponents(string: trimmed),
              let scheme = components.scheme?.lowercased() else {
            return nil
        }

        if directHostSchemes.contains(scheme) {
            return normalize(components.host)
        }
        switch scheme {
        case "ss":
            if components.port != nil, let host = normalize(components.host) {
                return host
            }
            return legacyShadowsocksHost(in: trimmed)
        case "vmess":
            return vmessHost(in: trimmed)
        default:
            return nil
        }
    }

    private static func legacyShadowsocksHost(in link: String) -> String? {
        guard let payload = payload(afterSchemeIn: link),
              let decoded = Data.flexibleBase64Decoded(payload),
              let authority = String(data: decoded, encoding: .utf8),
              let components = URLComponents(string: "ss://\(authority)"),
              components.port != nil else {
            return nil
        }
        return normalize(components.host)
    }

    private static func vmessHost(in link: String) -> String? {
        guard let payload = payload(afterSchemeIn: link),
              let decoded = Data.flexibleBase64Decoded(payload),
              let object = try? JSONSerialization.jsonObject(with: decoded),
              let dictionary = object as? [String: Any] else {
            return nil
        }
        for key in ["add", "address"] {
            if let host = normalize(dictionary[key] as? String) {
                return host
            }
        }
        return nil
    }

    private static func payload(afterSchemeIn link: String) -> String? {
        guard let separator = link.range(of: "://") else { return nil }
        let suffix = link[separator.upperBound...]
        let end = suffix.firstIndex(where: { $0 == "#" || $0 == "?" }) ?? suffix.endIndex
        let payload = String(suffix[..<end])
        return payload.isEmpty ? nil : payload
    }

    private static func normalize(_ value: String?) -> String? {
        guard var value = value?.trimmingCharacters(in: .whitespacesAndNewlines),
              !value.isEmpty else {
            return nil
        }
        if value.hasPrefix("["), value.hasSuffix("]"), value.count > 2 {
            value.removeFirst()
            value.removeLast()
        }
        return value.isEmpty ? nil : value
    }
}

enum TunnelRouteResolverError: Error {
    case unresolvedEndpoint
}

enum TunnelRouteResolver {
    static func resolve(hosts: [String]) throws -> [TunnelIPAddress] {
        var result: [TunnelIPAddress] = []
        var seen = Set<TunnelIPAddress>()

        for host in hosts {
            var addresses: UnsafeMutablePointer<addrinfo>?
            let status = host.withCString { getaddrinfo($0, nil, nil, &addresses) }
            guard status == 0, let first = addresses else {
                throw TunnelRouteResolverError.unresolvedEndpoint
            }
            defer { freeaddrinfo(first) }

            var cursor: UnsafeMutablePointer<addrinfo>? = first
            var foundForHost = false
            while let current = cursor {
                let entry = current.pointee
                cursor = entry.ai_next
                guard entry.ai_family == AF_INET || entry.ai_family == AF_INET6,
                      let socketAddress = entry.ai_addr else {
                    continue
                }

                var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                let nameStatus = getnameinfo(
                    socketAddress,
                    entry.ai_addrlen,
                    &buffer,
                    socklen_t(buffer.count),
                    nil,
                    0,
                    NI_NUMERICHOST
                )
                guard nameStatus == 0 else { continue }
                var numeric = String(cString: buffer)
                if let scope = numeric.firstIndex(of: "%") {
                    numeric.removeSubrange(scope...)
                }
                let family: TunnelIPAddress.Family = entry.ai_family == AF_INET ? .ipv4 : .ipv6
                let address = TunnelIPAddress(value: numeric, family: family)
                if seen.insert(address).inserted {
                    result.append(address)
                }
                foundForHost = true
            }
            guard foundForHost else {
                throw TunnelRouteResolverError.unresolvedEndpoint
            }
        }
        return result
    }
}
