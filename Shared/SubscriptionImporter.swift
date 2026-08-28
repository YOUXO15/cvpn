import Foundation

actor SubscriptionImporter {
    private let policy: SecurityPolicy
    private let client: PinnedHTTPSClient

    init(policy: SecurityPolicy) {
        self.policy = policy
        self.client = PinnedHTTPSClient(policy: policy)
    }

    func importInput(_ input: String) async throws -> [ImportedProfile] {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.utf8.count <= 16_384,
              let components = URLComponents(string: trimmed),
              let scheme = components.scheme?.lowercased() else {
            throw ClientError.invalidLink
        }

        if scheme == "https" {
            guard let url = components.url, let host = url.host?.lowercased() else {
                throw ClientError.invalidLink
            }
            let responseData = try await client.fetch(url)
            let payloadData: Data
            if let envelope = try? JSONDecoder().decode(SignedConfigEnvelope.self, from: responseData) {
                payloadData = try envelope.verifiedPayload(policy: policy)
            } else if policy.requireSignedEnvelope && !policy.allowsRawSubscription(host: host) {
                throw ClientError.unsignedConfiguration
            } else {
                payloadData = responseData
            }
            return try ConfigDocumentParser.parse(payloadData, sourceHost: host)
        }

        if ["vless", "vmess", "trojan", "ss"].contains(scheme) {
            return try ConfigDocumentParser.parse(Data(trimmed.utf8))
        }
        throw ClientError.invalidLink
    }
}
