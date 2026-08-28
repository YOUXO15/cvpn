import CryptoKit
import Foundation
import Security

enum PinnedURLPolicy {
    static func validatedHost(for url: URL, policy: SecurityPolicy) -> String? {
        guard url.scheme?.lowercased() == "https",
              url.user == nil,
              url.password == nil,
              url.fragment == nil,
              url.port == nil || url.port == 443,
              let host = url.host?.lowercased(),
              policy.allows(host: host),
              !policy.normalizedPins(for: host).isEmpty else {
            return nil
        }
        return host
    }

    static func allowsRedirect(
        from source: URL,
        to destination: URL,
        policy: SecurityPolicy
    ) -> Bool {
        guard let sourceHost = validatedHost(for: source, policy: policy),
              let destinationHost = validatedHost(for: destination, policy: policy),
              sourceHost == destinationHost else {
            return false
        }
        return effectiveHTTPSPort(source) == effectiveHTTPSPort(destination)
    }

    private static func effectiveHTTPSPort(_ url: URL) -> Int {
        url.port ?? 443
    }
}

final class PinnedSessionDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate, @unchecked Sendable {
    private let policy: SecurityPolicy

    init(policy: SecurityPolicy) {
        self.policy = policy
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        let host = challenge.protectionSpace.host.lowercased()
        let expectedPins = policy.normalizedPins(for: host)
        guard policy.allows(host: host), !expectedPins.isEmpty else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        var trustError: CFError?
        guard SecTrustEvaluateWithError(trust, &trustError), chainMatches(trust: trust, pins: expectedPins) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) {
        guard let source = response.url,
              let destination = request.url,
              PinnedURLPolicy.allowsRedirect(
                from: source,
                to: destination,
                policy: policy
              ) else {
            completionHandler(nil)
            return
        }
        completionHandler(request)
    }

    private func chainMatches(trust: SecTrust, pins: Set<String>) -> Bool {
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] else {
            return false
        }
        return chain.contains { certificate in
            guard let spki = try? DERSubjectPublicKeyInfo.extract(from: certificate) else {
                return false
            }
            return pins.contains(Data(SHA256.hash(data: spki)).base64EncodedString())
        }
    }
}

actor PinnedHTTPSClient {
    private let policy: SecurityPolicy
    private let session: URLSession

    init(policy: SecurityPolicy) {
        self.policy = policy
        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.timeoutIntervalForRequest = 20
        configuration.timeoutIntervalForResource = 30
        configuration.waitsForConnectivity = false
        self.session = URLSession(
            configuration: configuration,
            delegate: PinnedSessionDelegate(policy: policy),
            delegateQueue: nil
        )
    }

    func fetch(_ url: URL) async throws -> Data {
        guard PinnedURLPolicy.validatedHost(for: url, policy: policy) != nil else {
            throw ClientError.untrustedHost
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.setValue(
            "application/vnd.client.config+json, application/json, text/plain",
            forHTTPHeaderField: "Accept"
        )
        request.setValue("TunnelClient/0.2 iOS", forHTTPHeaderField: "User-Agent")

        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await session.data(for: request)
        } catch let error as URLError where error.code == .cancelled || error.code == .secureConnectionFailed || error.code == .serverCertificateUntrusted {
            throw ClientError.pinMismatch
        }

        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw ClientError.invalidServerResponse
        }
        guard data.count <= policy.maximumResponseBytes else {
            throw ClientError.responseTooLarge
        }
        return data
    }
}
