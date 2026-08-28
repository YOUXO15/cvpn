import CryptoKit
import Foundation

struct SignedConfigEnvelope: Codable, Sendable, Equatable {
    let version: Int
    let keyId: String
    let issuedAt: Int64
    let expiresAt: Int64
    let payload: String
    let signature: String

    func verifiedPayload(policy: SecurityPolicy, now: Date = Date()) throws -> Data {
        guard version == 1,
              issuedAt <= expiresAt,
              expiresAt - issuedAt <= 31 * 24 * 60 * 60 else {
            throw ClientError.invalidServerResponse
        }

        let nowSeconds = Int64(now.timeIntervalSince1970)
        guard issuedAt <= nowSeconds + 300, expiresAt >= nowSeconds - 300 else {
            throw ClientError.expiredConfiguration
        }

        guard let encodedKey = policy.signingKeys[keyId],
              let keyData = Data.flexibleBase64Decoded(encodedKey),
              let signatureData = Data.flexibleBase64Decoded(signature),
              let payloadData = Data.flexibleBase64Decoded(payload) else {
            throw ClientError.invalidSignature
        }

        let key: Curve25519.Signing.PublicKey
        do {
            key = try Curve25519.Signing.PublicKey(rawRepresentation: keyData)
        } catch {
            throw ClientError.invalidSignature
        }

        guard key.isValidSignature(signatureData, for: signingBytes) else {
            throw ClientError.invalidSignature
        }
        return payloadData
    }

    var signingBytes: Data {
        Data("\(version)\n\(keyId)\n\(issuedAt)\n\(expiresAt)\n\(payload)".utf8)
    }
}

extension Data {
    static func flexibleBase64Decoded(_ value: String) -> Data? {
        var normalized = value.filter { !$0.isWhitespace }
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        guard !normalized.isEmpty else { return nil }
        let remainder = normalized.count % 4
        if remainder != 0 {
            normalized.append(String(repeating: "=", count: 4 - remainder))
        }
        return Data(base64Encoded: normalized)
    }
}
