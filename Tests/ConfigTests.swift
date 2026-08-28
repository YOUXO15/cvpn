import Foundation
import Darwin
import NetworkExtension
import SwiftyXrayKit
import XCTest
@testable import TunnelClient

final class ConfigTests: XCTestCase {
    func testFullTunnelPolicyDoesNotEnforceDefaultRouteWithExclusions() {
        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.enforceRoutes = true
        tunnelProtocol.includeAllNetworks = true

        TunnelRoutingPolicy.apply(to: tunnelProtocol)

        XCTAssertFalse(tunnelProtocol.enforceRoutes)
        XCTAssertFalse(tunnelProtocol.includeAllNetworks)
    }

    func testSystemDNSUsesManagedBridgeVirtualResolver() {
        XCTAssertEqual(AppConstants.virtualDNSServers, ["198.18.0.1"])
        XCTAssertFalse(
            AppConstants.virtualDNSServers.contains {
                XrayConfigHardener.directBootstrapAddresses.contains($0)
            }
        )
    }

    func testSocksInboundBuilderReplacesUntrustedInbound() throws {
        let source: [String: Any] = [
            "inbounds": [[
                "listen": "0.0.0.0",
                "port": 80,
                "protocol": "http"
            ]],
            "outbounds": [["protocol": "freedom", "tag": "direct"]]
        ]
        let credentials = LocalSocksCredentials(
            port: 10_808,
            username: "local-user",
            password: "local-password"
        )

        let result = try XraySocksInboundBuilder.replacingInbounds(
            in: source,
            credentials: credentials
        )
        let inbounds = try XCTUnwrap(result["inbounds"] as? [[String: Any]])
        let inbound = try XCTUnwrap(inbounds.first)
        let settings = try XCTUnwrap(inbound["settings"] as? [String: Any])
        let accounts = try XCTUnwrap(settings["accounts"] as? [[String: String]])

        XCTAssertEqual(inbounds.count, 1)
        XCTAssertEqual(inbound["listen"] as? String, "127.0.0.1")
        XCTAssertEqual(inbound["port"] as? Int, credentials.port)
        XCTAssertEqual(inbound["protocol"] as? String, "socks")
        XCTAssertEqual(inbound["tag"] as? String, "in_proxy")
        XCTAssertEqual(settings["auth"] as? String, "password")
        XCTAssertEqual(settings["udp"] as? Bool, true)
        XCTAssertEqual(accounts, [[
            "user": credentials.username,
            "pass": credentials.password
        ]])
        XCTAssertEqual((result["outbounds"] as? [[String: String]])?.first?["tag"], "direct")
    }

    func testSocksInboundBuilderRejectsInvalidCredentials() {
        XCTAssertThrowsError(try XraySocksInboundBuilder.replacingInbounds(
            in: ["outbounds": [["protocol": "freedom"]]],
            credentials: LocalSocksCredentials(port: 0, username: "", password: "")
        )) { error in
            XCTAssertEqual(error as? ClientError, .unsupportedConfiguration)
        }
    }

    func testExtractsOnlyProxyServerEndpointsForRouteExclusions() throws {
        let config: [String: Any] = [
            "outbounds": [
                [
                    "protocol": "vless",
                    "settings": ["vnext": [["address": "edge.example", "port": 443]]]
                ],
                [
                    "protocol": "shadowsocks",
                    "settings": ["servers": [["address": "203.0.113.7", "port": 8388]]]
                ],
                [
                    "protocol": "trojan",
                    "settings": ["address": "direct.example", "port": 443]
                ],
                ["protocol": "dns", "tag": "dns-out"],
                ["protocol": "freedom", "tag": "direct"]
            ]
        ]

        XCTAssertEqual(
            XrayOutboundEndpointExtractor.hosts(in: config),
            ["edge.example", "203.0.113.7", "direct.example"]
        )
    }

    func testResolvesLiteralIPv4AndIPv6RouteAddresses() throws {
        let addresses = try TunnelRouteResolver.resolve(
            hosts: ["203.0.113.7", "2001:db8::7"]
        )

        XCTAssertTrue(addresses.contains(TunnelIPAddress(value: "203.0.113.7", family: .ipv4)))
        XCTAssertTrue(addresses.contains(TunnelIPAddress(value: "2001:db8::7", family: .ipv6)))
    }

    func testExtractsEndpointDirectlyFromVLESSShareLink() {
        let link = "vless://00000000-0000-0000-0000-000000000004@203.0.113.7:443?security=reality#Client"

        XCTAssertEqual(ShareLinkEndpointExtractor.host(in: link), "203.0.113.7")
    }

    func testExtractsEndpointDirectlyFromSIP002ShadowsocksShareLink() {
        let credentials = Data("chacha20-ietf-poly1305:test-password-value".utf8)
            .base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
        let link = "ss://\(credentials)@edge.example:8388#Client"

        XCTAssertEqual(ShareLinkEndpointExtractor.host(in: link), "edge.example")
    }

    func testExtractsEndpointFromLegacyShadowsocksShareLink() {
        let authority = Data("aes-256-gcm:test-password-value@198.51.100.8:443".utf8)
            .base64EncodedString()
            .replacingOccurrences(of: "=", with: "")

        XCTAssertEqual(
            ShareLinkEndpointExtractor.host(in: "ss://\(authority)#Client"),
            "198.51.100.8"
        )
    }

    func testExtractsEndpointFromVMessShareLink() throws {
        let document: [String: Any] = [
            "v": "2",
            "add": "vmess.example",
            "port": "443",
            "id": "00000000-0000-0000-0000-000000000001"
        ]
        let data = try JSONSerialization.data(withJSONObject: document, options: [.sortedKeys])
        let payload = data.base64EncodedString().replacingOccurrences(of: "=", with: "")

        XCTAssertEqual(
            ShareLinkEndpointExtractor.host(in: "vmess://\(payload)"),
            "vmess.example"
        )
    }

    func testTrafficSnapshotProviderMessageContainsNoProfileMaterial() throws {
        let snapshot = TunnelTrafficSnapshot(
            sentBytes: 1_024,
            receivedBytes: 2_048,
            sentPackets: 3,
            receivedPackets: 2,
            transportReady: true,
            outboundInterfaceBound: true
        )
        let encoded = try JSONEncoder().encode(snapshot)
        let decoded = try JSONDecoder().decode(TunnelTrafficSnapshot.self, from: encoded)

        XCTAssertEqual(decoded, snapshot)
        XCTAssertEqual(
            TunnelProviderMessage.trafficSnapshotRequest,
            Data("tunnel-traffic-v1".utf8)
        )
        XCTAssertFalse(String(decoding: encoded, as: UTF8.self).contains("profile"))
        XCTAssertFalse(String(decoding: encoded, as: UTF8.self).contains("vless"))
        XCTAssertFalse(String(decoding: encoded, as: UTF8.self).contains("host"))
    }

    func testDarwinTunDatagramCodecRoundTripsIPv4AndIPv6() throws {
        var ipv4 = Data(repeating: 0, count: 20)
        ipv4[0] = 0x45
        ipv4[2] = 0
        ipv4[3] = 20
        ipv4[8] = 64
        let ipv4Frame = try XCTUnwrap(XrayTunDatagramCodec.encode(
            packet: ipv4,
            protocolNumber: NSNumber(value: UInt32(AF_INET))
        ))
        let decodedIPv4 = try XCTUnwrap(XrayTunDatagramCodec.decode(ipv4Frame))
        XCTAssertEqual(decodedIPv4.packet, ipv4)
        XCTAssertEqual(decodedIPv4.protocolNumber.uint32Value, UInt32(AF_INET))

        var ipv6 = Data(repeating: 0, count: 40)
        ipv6[0] = 0x60
        let ipv6Frame = try XCTUnwrap(XrayTunDatagramCodec.encode(
            packet: ipv6,
            protocolNumber: NSNumber(value: UInt32(AF_INET6))
        ))
        let decodedIPv6 = try XCTUnwrap(XrayTunDatagramCodec.decode(ipv6Frame))
        XCTAssertEqual(decodedIPv6.packet, ipv6)
        XCTAssertEqual(decodedIPv6.protocolNumber.uint32Value, UInt32(AF_INET6))
    }

    func testDarwinTunDatagramCodecRejectsSplitOrTruncatedFrames() {
        XCTAssertNil(XrayTunDatagramCodec.decode(Data([0, 0, 0, UInt8(AF_INET)])))

        var truncatedIPv4 = Data(repeating: 0, count: 20)
        truncatedIPv4[0] = 0x45
        truncatedIPv4[2] = 0
        truncatedIPv4[3] = 40
        XCTAssertNil(XrayTunDatagramCodec.encode(
            packet: truncatedIPv4,
            protocolNumber: NSNumber(value: UInt32(AF_INET))
        ))
    }

    func testEmbeddedLibXrayConvertsRemnawaveWebSocketVLESS() throws {
        let link = "vless://00000000-0000-0000-0000-000000000004@edge.example:443?encryption=none&security=tls&sni=edge.example&fp=chrome&type=ws&host=edge.example&path=%2Fclient-ws#Client%20WS"

        let converted = try SwiftyXray.xrayShareLinkToJson(url: link)
        let data = try XCTUnwrap(converted.data(using: .utf8))
        let config = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
        let outbounds = try XCTUnwrap(config["outbounds"] as? [[String: Any]])
        let proxy = try XCTUnwrap(outbounds.first)
        let streamSettings = try XCTUnwrap(proxy["streamSettings"] as? [String: Any])

        XCTAssertEqual(proxy["protocol"] as? String, "vless")
        XCTAssertEqual(streamSettings["network"] as? String, "ws")
        XCTAssertEqual(streamSettings["security"] as? String, "tls")

        let hardened = try XrayConfigHardener.harden(config)
        XCTAssertNotNil(hardened["dns"])
        XCTAssertNotNil(hardened["routing"])
        XCTAssertEqual(
            XrayOutboundEndpointExtractor.hosts(in: hardened),
            ["edge.example"]
        )
    }

    func testEmbeddedLibXrayConvertsRemnawaveRealityVisionVLESS() throws {
        let link = "vless://00000000-0000-0000-0000-000000000005@reality.example:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9_AsrhtHHw&sid=0123456789abcdef&type=tcp&flow=xtls-rprx-vision#Client%20Reality"

        let config = try convertedConfig(from: link)
        let proxy = try firstProxyOutbound(in: config)
        let streamSettings = try XCTUnwrap(proxy["streamSettings"] as? [String: Any])

        XCTAssertEqual(proxy["protocol"] as? String, "vless")
        XCTAssertEqual(streamSettings["security"] as? String, "reality")

        let hardened = try XrayConfigHardener.harden(config)
        let hardenedProxy = try firstProxyOutbound(in: hardened)
        let hardenedStream = try XCTUnwrap(hardenedProxy["streamSettings"] as? [String: Any])
        let reality = try XCTUnwrap(hardenedStream["realitySettings"] as? [String: Any])

        XCTAssertEqual(reality["serverName"] as? String, "www.microsoft.com")
        XCTAssertNil(reality["dest"])
        XCTAssertNil(reality["target"])
        XCTAssertNil(reality["serverNames"])
        XCTAssertNil(reality["privateKey"])
        XCTAssertNil(reality["shortIds"])
        XCTAssertEqual(
            XrayOutboundEndpointExtractor.hosts(in: hardened),
            ["reality.example"]
        )
    }

    func testEmbeddedLibXrayConvertsRemnawaveXHTTPVLESS() throws {
        let link = "vless://00000000-0000-0000-0000-000000000006@xhttp.example:443?encryption=none&security=tls&sni=xhttp.example&fp=chrome&type=xhttp&host=xhttp.example&path=%2Fclient-xhttp&mode=auto#Client%20XHTTP"

        let config = try convertedConfig(from: link)
        let proxy = try firstProxyOutbound(in: config)
        let streamSettings = try XCTUnwrap(proxy["streamSettings"] as? [String: Any])

        XCTAssertEqual(proxy["protocol"] as? String, "vless")
        XCTAssertEqual(streamSettings["network"] as? String, "xhttp")
        XCTAssertEqual(streamSettings["security"] as? String, "tls")
        XCTAssertNoThrow(try XrayConfigHardener.harden(config))
    }

    func testHardenerMakesShadowsocksProfileWithFragmentStartable() throws {
        let credentials = Data("chacha20-ietf-poly1305:test-password-value".utf8)
            .base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
        let link = "ss://\(credentials)@203.0.113.7:8388#France%20Auto"

        let converted = try convertedConfig(from: link)
        let hardened = try XrayConfigHardener.harden(converted)
        let proxy = try firstProxyOutbound(in: hardened)

        XCTAssertEqual(proxy["protocol"] as? String, "shadowsocks")
        XCTAssertNil(proxy["sendThrough"])
        XCTAssertEqual(
            XrayOutboundEndpointExtractor.hosts(in: hardened),
            ["203.0.113.7"]
        )
    }

    func testDisconnectDiagnosticExplainsMissingNetworkExtensionEntitlement() {
        let message = VPNDisconnectDiagnostic.message(for: nil)

        XCTAssertTrue(message.contains("Network Extension"))
        XCTAssertTrue(message.contains("Packet Tunnel"))
    }

    func testDisconnectDiagnosticExplainsDisabledPlugin() {
        let error = NSError(
            domain: NEVPNConnectionErrorDomain,
            code: NEVPNConnectionError.pluginDisabled.rawValue
        )

        let message = VPNDisconnectDiagnostic.message(for: error)

        XCTAssertTrue(message.contains("Packet Tunnel"))
        XCTAssertTrue(message.contains("Network Extension"))
    }

    func testDisconnectDiagnosticDoesNotExposeProviderErrorDetails() {
        let error = NSError(
            domain: "SwiftyXrayKit.SwiftyXRayError",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: "vless://secret-profile-value"]
        )

        let message = VPNDisconnectDiagnostic.message(for: error)

        XCTAssertFalse(message.contains("vless"))
        XCTAssertFalse(message.contains("secret-profile-value"))
        XCTAssertTrue(message.contains("Содержимое VPN-профиля скрыто"))
    }

    func testSelectsActualEmbeddedPacketTunnelBundleIdentifier() {
        let candidates = [
            EmbeddedTunnelBundleLocator.Candidate(
                bundleIdentifier: "signed.example.Widget",
                extensionPointIdentifier: "com.apple.widgetkit-extension"
            ),
            EmbeddedTunnelBundleLocator.Candidate(
                bundleIdentifier: "signed.example.PacketTunnel",
                extensionPointIdentifier: EmbeddedTunnelBundleLocator.packetTunnelExtensionPoint
            )
        ]

        XCTAssertEqual(
            EmbeddedTunnelBundleLocator.selectIdentifier(
                from: candidates,
                fallback: AppConstants.defaultTunnelBundleIdentifier
            ),
            "signed.example.PacketTunnel"
        )
    }

    func testFallsBackWhenEmbeddedPacketTunnelCannotBeInspected() {
        XCTAssertEqual(
            EmbeddedTunnelBundleLocator.selectIdentifier(
                from: [],
                fallback: AppConstants.defaultTunnelBundleIdentifier
            ),
            AppConstants.defaultTunnelBundleIdentifier
        )
    }

    func testParsesHAPPStyleArrayIntoIndependentProfiles() throws {
        let data = Data("""
        [
          {"remarks":"Finland (WiFi)","outbounds":[{"protocol":"vless","tag":"proxy"}]},
          {"remarks":"Finland LTE","outbounds":[{"protocol":"vless","tag":"proxy"}]}
        ]
        """.utf8)

        let profiles = try ConfigDocumentParser.parse(data, sourceHost: "config.example")

        XCTAssertEqual(profiles.map(\.suggestedName), ["Finland (WiFi)", "Finland LTE"])
        XCTAssertTrue(profiles.allSatisfy { $0.payload.kind == .xrayJSON })
        XCTAssertTrue(profiles.allSatisfy { $0.sourceHost == "config.example" })
    }

    func testParsesVLESSShareLinkWithoutNetworkAccess() throws {
        let input = Data("vless://00000000-0000-0000-0000-000000000000@example.com:443?security=tls#Test%20Profile".utf8)

        let profiles = try ConfigDocumentParser.parse(input)

        XCTAssertEqual(profiles.count, 1)
        XCTAssertEqual(profiles[0].suggestedName, "Test Profile")
        XCTAssertEqual(profiles[0].payload.kind, .shareLink)
    }

    func testParsesRemnawaveBase64SubscriptionWithWhitespace() throws {
        let links = """
        vless://00000000-0000-0000-0000-000000000001@fi.example:443?security=tls#Finland
        vless://00000000-0000-0000-0000-000000000002@de.example:443?security=tls#Germany
        """
        let encoded = Data(links.utf8).base64EncodedString()
        let wrapped = stride(from: 0, to: encoded.count, by: 24).map { offset in
            let start = encoded.index(encoded.startIndex, offsetBy: offset)
            let end = encoded.index(start, offsetBy: min(24, encoded.distance(from: start, to: encoded.endIndex)))
            return String(encoded[start..<end])
        }.joined(separator: "\r\n")

        let profiles = try ConfigDocumentParser.parse(Data(wrapped.utf8), sourceHost: "sub-one.example.invalid")

        XCTAssertEqual(profiles.map(\.suggestedName), ["Finland", "Germany"])
        XCTAssertTrue(profiles.allSatisfy { $0.payload.kind == .shareLink })
        XCTAssertTrue(profiles.allSatisfy { $0.sourceHost == "sub-one.example.invalid" })
    }

    func testTunnelPayloadRoundTripsThroughStartOptions() throws {
        let payload = StoredProfilePayload(
            kind: .shareLink,
            content: "vless://00000000-0000-0000-0000-000000000003@fi.example:443"
        )
        let data = try TunnelProfilePayload.encode(payload)
        let decoded = try TunnelProfilePayload.decode(from: [
            AppConstants.providerProfilePayloadKey: data as NSData
        ])

        XCTAssertEqual(decoded, payload)
    }

    func testTunnelPayloadRejectsMalformedStartOption() throws {
        XCTAssertThrowsError(try TunnelProfilePayload.decode(from: [
            AppConstants.providerProfilePayloadKey: Data("not-json".utf8) as NSData
        ])) { error in
            XCTAssertEqual(error as? ClientError, .missingProfile)
        }
    }

    func testHardenerRemovesRemoteControlAndAddsDNSInterception() throws {
        let source: [String: Any] = [
            "api": ["tag": "api"],
            "reverse": ["bridges": []],
            "outbounds": [[
                "protocol": "vless",
                "tag": "proxy",
                "sendThrough": "profile-name-is-not-an-address"
            ]]
        ]

        let hardened = try XrayConfigHardener.harden(source)
        let outbounds = try XCTUnwrap(hardened["outbounds"] as? [[String: Any]])
        let routing = try XCTUnwrap(hardened["routing"] as? [String: Any])
        let rules = try XCTUnwrap(routing["rules"] as? [[String: Any]])

        XCTAssertNil(hardened["api"])
        XCTAssertNil(hardened["reverse"])
        XCTAssertTrue(outbounds.contains { ($0["tag"] as? String) == "dns-out" })
        XCTAssertNil(outbounds.first?["sendThrough"])
        XCTAssertEqual(rules.first?["outboundTag"] as? String, "dns-out")
    }

    func testHardenerBindsEveryOutboundToPhysicalInterface() throws {
        let source: [String: Any] = [
            "outbounds": [
                [
                    "protocol": "vless",
                    "streamSettings": [
                        "security": "reality",
                        "sockopt": [
                            "interface": "utun99",
                            "tcpFastOpen": true
                        ]
                    ]
                ],
                ["protocol": "freedom", "tag": "direct"]
            ]
        ]

        let hardened = try XrayConfigHardener.harden(source, egressInterface: "en0")
        let outbounds = try XCTUnwrap(hardened["outbounds"] as? [[String: Any]])

        for outbound in outbounds {
            let stream = try XCTUnwrap(outbound["streamSettings"] as? [String: Any])
            let socketOptions = try XCTUnwrap(stream["sockopt"] as? [String: Any])
            XCTAssertEqual(socketOptions["interface"] as? String, "en0")
        }
        let proxyStream = try XCTUnwrap(outbounds.first?["streamSettings"] as? [String: Any])
        let proxySocketOptions = try XCTUnwrap(proxyStream["sockopt"] as? [String: Any])
        XCTAssertEqual(proxySocketOptions["tcpFastOpen"] as? Bool, true)
    }

    func testHardenerRejectsInvalidPhysicalInterfaceName() {
        XCTAssertThrowsError(try XrayConfigHardener.harden(
            ["outbounds": [["protocol": "vless"]]],
            egressInterface: "utun0\nsecret"
        ))
    }

    func testHardenerRemovesSubscriptionProvidedInterfaceWithoutTrustedBinding() throws {
        let source: [String: Any] = [
            "outbounds": [[
                "protocol": "vless",
                "streamSettings": ["sockopt": ["interface": "utun99"]]
            ]]
        ]

        let hardened = try XrayConfigHardener.harden(source)
        let proxy = try firstProxyOutbound(in: hardened)
        let stream = proxy["streamSettings"] as? [String: Any]
        let socketOptions = stream?["sockopt"] as? [String: Any]

        XCTAssertNil(socketOptions?["interface"])
    }

    func testHardenerDropsRealityServerMaterialFromSubscription() throws {
        let source: [String: Any] = [
            "outbounds": [[
                "protocol": "vless",
                "streamSettings": [
                    "security": "reality",
                    "realitySettings": [
                        "serverName": "allowed-client-name.example",
                        "publicKey": "allowed-client-public-key",
                        "shortId": "0123456789abcdef",
                        "dest": NSNull(),
                        "serverNames": [],
                        "privateKey": "must-not-reach-client-core",
                        "shortIds": ["server-only"],
                        "masterKeyLog": "/tmp/forbidden"
                    ]
                ]
            ]]
        ]

        let hardened = try XrayConfigHardener.harden(source)
        let proxy = try firstProxyOutbound(in: hardened)
        let stream = try XCTUnwrap(proxy["streamSettings"] as? [String: Any])
        let reality = try XCTUnwrap(stream["realitySettings"] as? [String: Any])

        XCTAssertEqual(reality["serverName"] as? String, "allowed-client-name.example")
        XCTAssertEqual(reality["publicKey"] as? String, "allowed-client-public-key")
        XCTAssertEqual(reality["shortId"] as? String, "0123456789abcdef")
        XCTAssertNil(reality["dest"])
        XCTAssertNil(reality["serverNames"])
        XCTAssertNil(reality["privateKey"])
        XCTAssertNil(reality["shortIds"])
        XCTAssertNil(reality["masterKeyLog"])
    }

    func testDisconnectDiagnosticReportsSanitizedTunnelStage() {
        let error = TunnelStartupError.engineStart as NSError

        let message = VPNDisconnectDiagnostic.message(for: error)

        XCTAssertTrue(message.contains("этап 4"))
        XCTAssertTrue(message.contains("Секретные параметры скрыты"))
        XCTAssertFalse(message.contains("test-password"))
    }

    func testRoutePreparationDiagnosticDoesNotExposeEndpoint() {
        let message = VPNDisconnectDiagnostic.message(
            for: TunnelStartupError.routeEndpointExtraction as NSError
        )

        XCTAssertTrue(message.contains("этап 5"))
        XCTAssertTrue(message.contains("Секретные параметры скрыты"))
        XCTAssertFalse(message.contains("example.com"))
    }

    func testRouteResolutionDiagnosticDoesNotExposeEndpoint() {
        let message = VPNDisconnectDiagnostic.message(
            for: TunnelStartupError.routeResolution as NSError
        )

        XCTAssertTrue(message.contains("этап 6"))
        XCTAssertTrue(message.contains("Секретные параметры скрыты"))
        XCTAssertFalse(message.contains("example.com"))
    }

    func testEgressInterfaceDiagnosticDoesNotExposeConfiguration() {
        let message = VPNDisconnectDiagnostic.message(
            for: TunnelStartupError.egressInterfaceSelection as NSError
        )

        XCTAssertTrue(message.contains("этап 7"))
        XCTAssertTrue(message.contains("физический интернет-интерфейс"))
        XCTAssertFalse(message.contains("example.com"))
    }

    func testRuntimeBridgeDiagnosticContainsNoConfigurationMaterial() {
        let error = TunnelRuntimeError.transportBridgeExited as NSError

        let message = VPNDisconnectDiagnostic.message(for: error)

        XCTAssertTrue(message.contains("TUN-мост"))
        XCTAssertTrue(message.contains("не записывались"))
        XCTAssertFalse(message.contains("vless"))
        XCTAssertFalse(message.contains("example.com"))
        XCTAssertTrue(error.userInfo.isEmpty)
    }

    private func convertedConfig(from link: String) throws -> [String: Any] {
        let converted = try SwiftyXray.xrayShareLinkToJson(url: link)
        let data = try XCTUnwrap(converted.data(using: .utf8))
        return try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
    }

    private func firstProxyOutbound(in config: [String: Any]) throws -> [String: Any] {
        let outbounds = try XCTUnwrap(config["outbounds"] as? [[String: Any]])
        return try XCTUnwrap(outbounds.first)
    }
}
