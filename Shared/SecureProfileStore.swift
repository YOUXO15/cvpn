import Foundation
import Security

enum SecureProfileStore {
    private static var accessGroup: String? {
        // An unsigned IPA leaves AppIdentifierPrefix empty. Many re-signers do not
        // rewrite this Info.plist value, so only use it when a Team ID is present.
        guard let value = Bundle.main.object(forInfoDictionaryKey: "KeychainAccessGroup") as? String,
              !value.contains("$("), !value.isEmpty,
              let prefix = value.split(separator: ".", maxSplits: 1).first,
              prefix.count == 10,
              prefix.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }) else {
            return nil
        }
        return value
    }

    static func save(payload: StoredProfilePayload, id: UUID) throws {
        let data = try JSONEncoder().encode(payload)
        for query in candidateQueries(id: id) {
            var item = query
            SecItemDelete(item as CFDictionary)
            item[kSecValueData as String] = data
            item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            item[kSecUseDataProtectionKeychain as String] = true
            if SecItemAdd(item as CFDictionary, nil) == errSecSuccess {
                return
            }
        }
        throw ClientError.secureStorageFailure
    }

    static func load(id: UUID) throws -> StoredProfilePayload {
        for candidate in candidateQueries(id: id) {
            var query = candidate
            query[kSecReturnData as String] = true
            query[kSecMatchLimit as String] = kSecMatchLimitOne
            var item: CFTypeRef?
            guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
                  let data = item as? Data else {
                continue
            }
            guard let payload = try? JSONDecoder().decode(StoredProfilePayload.self, from: data) else {
                throw ClientError.missingProfile
            }
            return payload
        }
        throw ClientError.missingProfile
    }

    static func delete(id: UUID) throws {
        var failed = false
        for query in candidateQueries(id: id) {
            let status = SecItemDelete(query as CFDictionary)
            if status != errSecSuccess,
               status != errSecItemNotFound,
               status != errSecMissingEntitlement {
                failed = true
            }
        }
        if failed { throw ClientError.secureStorageFailure }
    }

    private static func candidateQueries(id: UUID) -> [[String: Any]] {
        var queries: [[String: Any]] = []
        if let accessGroup {
            queries.append(baseQuery(id: id, accessGroup: accessGroup))
        }
        queries.append(baseQuery(id: id, accessGroup: nil))
        return queries
    }

    private static func baseQuery(id: UUID, accessGroup: String?) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: AppConstants.keychainService,
            kSecAttrAccount as String: id.uuidString
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }
}

enum ProfileMetadataStore {
    static var defaults: UserDefaults {
        if FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: AppConstants.appGroupIdentifier
        ) != nil,
           let shared = UserDefaults(suiteName: AppConstants.appGroupIdentifier) {
            return shared
        }
        return .standard
    }

    static func load() -> [ProfileSummary] {
        guard let data = defaults.data(forKey: AppConstants.profileMetadataKey),
              let profiles = try? JSONDecoder().decode([ProfileSummary].self, from: data) else {
            return []
        }
        return profiles
    }

    static func save(_ profiles: [ProfileSummary]) throws {
        let data = try JSONEncoder().encode(profiles)
        defaults.set(data, forKey: AppConstants.profileMetadataKey)
    }
}
