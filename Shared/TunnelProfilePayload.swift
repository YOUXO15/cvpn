import Foundation

enum TunnelProfilePayload {
    static func encode(_ payload: StoredProfilePayload) throws -> Data {
        try JSONEncoder().encode(payload)
    }

    static func decode(from options: [String: NSObject]?) throws -> StoredProfilePayload? {
        guard let data = options?[AppConstants.providerProfilePayloadKey] as? NSData else {
            return nil
        }
        do {
            return try JSONDecoder().decode(StoredProfilePayload.self, from: data as Data)
        } catch {
            throw ClientError.missingProfile
        }
    }
}
