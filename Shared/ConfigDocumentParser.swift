import Foundation

enum ConfigDocumentParser {
    static func parse(_ data: Data, sourceHost: String? = nil) throws -> [ImportedProfile] {
        guard data.count <= 4 * 1024 * 1024 else { throw ClientError.responseTooLarge }

        if let object = try? JSONSerialization.jsonObject(with: data) {
            if let array = object as? [[String: Any]] {
                return try parseJSONProfiles(array, sourceHost: sourceHost)
            }
            if let dictionary = object as? [String: Any] {
                return [try makeJSONProfile(dictionary, index: 1, sourceHost: sourceHost)]
            }
        }

        guard let text = String(data: data, encoding: .utf8) else {
            throw ClientError.unsupportedConfiguration
        }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if let decoded = Data.flexibleBase64Decoded(trimmed),
           let decodedText = String(data: decoded, encoding: .utf8),
           decodedText.contains("://") {
            return try parseShareLinks(decodedText, sourceHost: sourceHost)
        }
        return try parseShareLinks(trimmed, sourceHost: sourceHost)
    }

    private static func parseJSONProfiles(
        _ profiles: [[String: Any]],
        sourceHost: String?
    ) throws -> [ImportedProfile] {
        guard !profiles.isEmpty, profiles.count <= AppConstants.maximumProfilesPerImport else {
            throw ClientError.unsupportedConfiguration
        }
        return try profiles.enumerated().map {
            try makeJSONProfile($0.element, index: $0.offset + 1, sourceHost: sourceHost)
        }
    }

    private static func makeJSONProfile(
        _ dictionary: [String: Any],
        index: Int,
        sourceHost: String?
    ) throws -> ImportedProfile {
        guard dictionary["outbounds"] is [[String: Any]] else {
            throw ClientError.unsupportedConfiguration
        }
        let encoded = try JSONSerialization.data(withJSONObject: dictionary, options: [.sortedKeys])
        guard let content = String(data: encoded, encoding: .utf8) else {
            throw ClientError.unsupportedConfiguration
        }
        let remarks = (dictionary["remarks"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        let name = remarks.flatMap { $0.isEmpty ? nil : $0 } ?? "VPN профиль \(index)"
        return ImportedProfile(
            suggestedName: name,
            sourceHost: sourceHost,
            payload: StoredProfilePayload(kind: .xrayJSON, content: content)
        )
    }

    private static func parseShareLinks(_ text: String, sourceHost: String?) throws -> [ImportedProfile] {
        let supportedSchemes = Set(["vless", "vmess", "trojan", "ss"])
        let lines = text.split(whereSeparator: \.isNewline).map(String.init)
        let profiles = lines.compactMap { line -> ImportedProfile? in
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard let components = URLComponents(string: trimmed),
                  let scheme = components.scheme?.lowercased(),
                  supportedSchemes.contains(scheme) else {
                return nil
            }
            let decodedName = components.fragment?.removingPercentEncoding?
                .trimmingCharacters(in: .whitespacesAndNewlines)
            let name = decodedName.flatMap { $0.isEmpty ? nil : $0 } ?? "VPN \(scheme.uppercased())"
            return ImportedProfile(
                suggestedName: name,
                sourceHost: sourceHost,
                payload: StoredProfilePayload(kind: .shareLink, content: trimmed)
            )
        }
        guard !profiles.isEmpty, profiles.count <= AppConstants.maximumProfilesPerImport else {
            throw ClientError.unsupportedConfiguration
        }
        return profiles
    }
}
