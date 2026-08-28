import Foundation

struct SecurityPolicy: Decodable, Sendable, Equatable {
    let version: Int
    let requireSignedEnvelope: Bool
    let maximumResponseBytes: Int
    let allowedHosts: [String]
    let rawSubscriptionHosts: [String]
    let spkiPins: [String: [String]]
    let signingKeys: [String: String]

    init(
        version: Int,
        requireSignedEnvelope: Bool,
        maximumResponseBytes: Int,
        allowedHosts: [String],
        rawSubscriptionHosts: [String] = [],
        spkiPins: [String: [String]],
        signingKeys: [String: String]
    ) {
        self.version = version
        self.requireSignedEnvelope = requireSignedEnvelope
        self.maximumResponseBytes = maximumResponseBytes
        self.allowedHosts = allowedHosts
        self.rawSubscriptionHosts = rawSubscriptionHosts
        self.spkiPins = spkiPins
        self.signingKeys = signingKeys
    }

    private enum CodingKeys: String, CodingKey {
        case version
        case requireSignedEnvelope
        case maximumResponseBytes
        case allowedHosts
        case rawSubscriptionHosts
        case spkiPins
        case signingKeys
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        requireSignedEnvelope = try container.decode(Bool.self, forKey: .requireSignedEnvelope)
        maximumResponseBytes = try container.decode(Int.self, forKey: .maximumResponseBytes)
        allowedHosts = try container.decode([String].self, forKey: .allowedHosts)
        rawSubscriptionHosts = try container.decodeIfPresent([String].self, forKey: .rawSubscriptionHosts) ?? []
        spkiPins = try container.decode([String: [String]].self, forKey: .spkiPins)
        signingKeys = try container.decode([String: String].self, forKey: .signingKeys)
    }

    static func load(bundle: Bundle = .main) throws -> SecurityPolicy {
        guard let url = bundle.url(forResource: "SecurityPolicy", withExtension: "plist") else {
            throw ClientError.invalidServerResponse
        }
        let data = try Data(contentsOf: url)
        let policy = try PropertyListDecoder().decode(SecurityPolicy.self, from: data)
        guard policy.version == 1,
              policy.maximumResponseBytes > 0,
              policy.maximumResponseBytes <= 4 * 1024 * 1024 else {
            throw ClientError.invalidServerResponse
        }
        return policy
    }

    func normalizedPins(for host: String) -> Set<String> {
        Set((spkiPins[host.lowercased()] ?? []).map(Self.normalizePin))
    }

    func allows(host: String) -> Bool {
        let candidate = host.lowercased()
        return allowedHosts.contains { $0.lowercased() == candidate }
    }

    func allowsRawSubscription(host: String) -> Bool {
        let candidate = host.lowercased()
        return rawSubscriptionHosts.contains { $0.lowercased() == candidate }
    }

    private static func normalizePin(_ value: String) -> String {
        value.hasPrefix("sha256/") ? String(value.dropFirst("sha256/".count)) : value
    }
}
