import CryptoKit
import XCTest
@testable import TunnelClient

final class SecurityTests: XCTestCase {
    func testSignedEnvelopeAcceptsValidEd25519Signature() throws {
        let privateKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: Data((0..<32).map(UInt8.init))
        )
        let payloadData = Data("[{\"remarks\":\"Test\",\"outbounds\":[{\"protocol\":\"freedom\"}]}]".utf8)
        let payload = payloadData.base64EncodedString()
        let unsigned = SignedConfigEnvelope(
            version: 1,
            keyId: "test",
            issuedAt: 1_700_000_000,
            expiresAt: 1_700_086_400,
            payload: payload,
            signature: ""
        )
        let signature = try privateKey.signature(for: unsigned.signingBytes).base64EncodedString()
        let envelope = SignedConfigEnvelope(
            version: unsigned.version,
            keyId: unsigned.keyId,
            issuedAt: unsigned.issuedAt,
            expiresAt: unsigned.expiresAt,
            payload: unsigned.payload,
            signature: signature
        )
        let policy = SecurityPolicy(
            version: 1,
            requireSignedEnvelope: true,
            maximumResponseBytes: 1_048_576,
            allowedHosts: ["config.example"],
            spkiPins: ["config.example": ["pin"]],
            signingKeys: ["test": privateKey.publicKey.rawRepresentation.base64EncodedString()]
        )

        XCTAssertEqual(
            try envelope.verifiedPayload(policy: policy, now: Date(timeIntervalSince1970: 1_700_000_100)),
            payloadData
        )
    }

    func testSignedEnvelopeRejectsExpiredPayload() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let unsigned = SignedConfigEnvelope(
            version: 1,
            keyId: "test",
            issuedAt: 1_700_000_000,
            expiresAt: 1_700_000_100,
            payload: Data("{}".utf8).base64EncodedString(),
            signature: ""
        )
        let envelope = SignedConfigEnvelope(
            version: 1,
            keyId: "test",
            issuedAt: unsigned.issuedAt,
            expiresAt: unsigned.expiresAt,
            payload: unsigned.payload,
            signature: try privateKey.signature(for: unsigned.signingBytes).base64EncodedString()
        )
        let policy = SecurityPolicy(
            version: 1,
            requireSignedEnvelope: true,
            maximumResponseBytes: 1_048_576,
            allowedHosts: [],
            spkiPins: [:],
            signingKeys: ["test": privateKey.publicKey.rawRepresentation.base64EncodedString()]
        )

        XCTAssertThrowsError(
            try envelope.verifiedPayload(policy: policy, now: Date(timeIntervalSince1970: 1_700_001_000))
        ) { error in
            XCTAssertEqual(error as? ClientError, .expiredConfiguration)
        }
    }

    func testSignedEnvelopeRejectsTamperedPayload() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let unsigned = SignedConfigEnvelope(
            version: 1,
            keyId: "test",
            issuedAt: 1_700_000_000,
            expiresAt: 1_700_000_900,
            payload: Data("{}".utf8).base64EncodedString(),
            signature: ""
        )
        let envelope = SignedConfigEnvelope(
            version: 1,
            keyId: "test",
            issuedAt: unsigned.issuedAt,
            expiresAt: unsigned.expiresAt,
            payload: Data("{\"tampered\":true}".utf8).base64EncodedString(),
            signature: try privateKey.signature(for: unsigned.signingBytes).base64EncodedString()
        )
        let policy = SecurityPolicy(
            version: 1,
            requireSignedEnvelope: true,
            maximumResponseBytes: 1_048_576,
            allowedHosts: [],
            spkiPins: [:],
            signingKeys: ["test": privateKey.publicKey.rawRepresentation.base64EncodedString()]
        )

        XCTAssertThrowsError(
            try envelope.verifiedPayload(policy: policy, now: Date(timeIntervalSince1970: 1_700_000_100))
        ) { error in
            XCTAssertEqual(error as? ClientError, .invalidSignature)
        }
    }

    func testSPKIPolicyRequiresExactHost() {
        let policy = SecurityPolicy(
            version: 1,
            requireSignedEnvelope: true,
            maximumResponseBytes: 1_048_576,
            allowedHosts: ["config.example"],
            spkiPins: ["config.example": ["sha256/abc"]],
            signingKeys: [:]
        )

        XCTAssertTrue(policy.allows(host: "CONFIG.EXAMPLE"))
        XCTAssertFalse(policy.allows(host: "sub.config.example"))
        XCTAssertEqual(policy.normalizedPins(for: "config.example"), ["abc"])
    }

    func testRawSubscriptionPolicyRequiresExactHost() {
        let policy = SecurityPolicy(
            version: 1,
            requireSignedEnvelope: true,
            maximumResponseBytes: 1_048_576,
            allowedHosts: ["sub.example"],
            rawSubscriptionHosts: ["sub.example"],
            spkiPins: ["sub.example": ["pin"]],
            signingKeys: [:]
        )

        XCTAssertTrue(policy.allowsRawSubscription(host: "SUB.EXAMPLE"))
        XCTAssertFalse(policy.allowsRawSubscription(host: "evil.sub.example"))
        XCTAssertFalse(policy.allowsRawSubscription(host: "example"))
    }

    func testPinnedURLPolicyRejectsAlternateOriginsAndURLCredentials() throws {
        let policy = SecurityPolicy(
            version: 1,
            requireSignedEnvelope: true,
            maximumResponseBytes: 1_048_576,
            allowedHosts: ["config.example"],
            spkiPins: ["config.example": ["pin"]],
            signingKeys: [:]
        )

        XCTAssertEqual(
            PinnedURLPolicy.validatedHost(
                for: try XCTUnwrap(URL(string: "https://config.example/subscription")),
                policy: policy
            ),
            "config.example"
        )
        XCTAssertEqual(
            PinnedURLPolicy.validatedHost(
                for: try XCTUnwrap(URL(string: "https://config.example:443/subscription")),
                policy: policy
            ),
            "config.example"
        )
        XCTAssertNil(PinnedURLPolicy.validatedHost(
            for: try XCTUnwrap(URL(string: "http://config.example/subscription")),
            policy: policy
        ))
        XCTAssertNil(PinnedURLPolicy.validatedHost(
            for: try XCTUnwrap(URL(string: "https://user:password@config.example/subscription")),
            policy: policy
        ))
        XCTAssertNil(PinnedURLPolicy.validatedHost(
            for: try XCTUnwrap(URL(string: "https://config.example:8443/subscription")),
            policy: policy
        ))
        XCTAssertNil(PinnedURLPolicy.validatedHost(
            for: try XCTUnwrap(URL(string: "https://evil.config.example/subscription")),
            policy: policy
        ))
        XCTAssertNil(PinnedURLPolicy.validatedHost(
            for: try XCTUnwrap(URL(string: "https://config.example/subscription#secret")),
            policy: policy
        ))
    }

    func testPinnedURLPolicyAllowsOnlySameOriginHTTPSRedirects() throws {
        let policy = SecurityPolicy(
            version: 1,
            requireSignedEnvelope: true,
            maximumResponseBytes: 1_048_576,
            allowedHosts: ["config.example"],
            spkiPins: ["config.example": ["pin"]],
            signingKeys: [:]
        )
        let source = try XCTUnwrap(URL(string: "https://config.example/old"))

        XCTAssertTrue(PinnedURLPolicy.allowsRedirect(
            from: source,
            to: try XCTUnwrap(URL(string: "https://config.example/new")),
            policy: policy
        ))
        XCTAssertFalse(PinnedURLPolicy.allowsRedirect(
            from: source,
            to: try XCTUnwrap(URL(string: "https://config.example:8443/new")),
            policy: policy
        ))
        XCTAssertFalse(PinnedURLPolicy.allowsRedirect(
            from: source,
            to: try XCTUnwrap(URL(string: "https://user@config.example/new")),
            policy: policy
        ))
        XCTAssertFalse(PinnedURLPolicy.allowsRedirect(
            from: source,
            to: try XCTUnwrap(URL(string: "https://evil.config.example/new")),
            policy: policy
        ))
    }
}
