import CryptoKit
import Security
import XCTest
@testable import TunnelClient

final class SecurityTests: XCTestCase {
    func testSPKIExtractorMatchesKnownRSAFixture() throws {
        let certificateData = try XCTUnwrap(Data(base64Encoded: "MIICzTCCAbWgAwIBAgIHQ0VLQ1BJTjANBgkqhkiG9w0BAQsFADAeMRwwGgYDVQQDDBNHZW5lcmljIFBpbiBGaXh0dXJlMB4XDTI1MDEwMTAwMDAwMFoXDTM1MDEwMTAwMDAwMFowHjEcMBoGA1UEAwwTR2VuZXJpYyBQaW4gRml4dHVyZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMJ3p+EaK/DW2gvCQX4rjzRRVRi18hfbZ5hE3+x/lGAYutHrqcEP7oZls47TYEKMIR/acbdrAmsJnJtbfQvj5xhST5cJSwu8rZMs+pIofQr+rhGsDWSPO2rLIrA2YKs+e1HS4bCGPHbkK+BtEyg3Nq4k4SYOfQh3hgeMpHrXRlEZeh3A1+36iTDEJs96n8D5Dley9YYBz1LxB+ZYWRw99ab8rxEZB5rkGIwJy6H6XWcioZ+WzIHzpmfENxTeYJ7oTMlHWmQP1TyswNxHHSR9vz7uX+9baozF3X85eWZxAUwtP/BW1gxBgv12JfH4sAiNqr4xeA+3PWwyYgCFBWZGis8CAwEAAaMQMA4wDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAa6zVNC1Vt7/JtENMB0/gHUGnJuDjR6hPN4cYyUv0/kXO2ZSC9aGT0zyJcqe69+VPINzKOuEI/HrJFQv79KgpCUcT7Z34Nn33yf0tEhj3iWvStxvbhbl3X5rttXV0v2Y+Af/3LfHoUJpD224cqa7HC8nl2qfQ6i3BRMESeKMJqiYiQLvx4WjyI270YS/6r6P9QJjUDk+G/I1OfcpVBWU36xI1MREhZDBIhJwLIXn19+AjBCAItuUwUhredmU7e2/LjbjPg81oJyLN3L0K0GlF0hm1UhN/0dpPnfPXlEd+oKN5RLpDPgR5tWCPvOYmne08kprQF/FierMofH75NY2meA=="))
        let certificate = try XCTUnwrap(
            SecCertificateCreateWithData(nil, certificateData as CFData)
        )

        let spki = try DERSubjectPublicKeyInfo.extract(from: certificate)
        let pin = Data(SHA256.hash(data: spki)).base64EncodedString()

        XCTAssertEqual(pin, "hAliG80t99479ipnrDIJldJqjg1mtizHRKgHkcGfVd8=")
    }

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
