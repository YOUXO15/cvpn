import Foundation
import NetworkExtension
import SwiftyXrayKit

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private struct PreparedCore {
        let bridge: SocksTunnelBridge
        let dataDirectory: URL
        let configURL: URL
        let routeAddresses: [TunnelIPAddress]
        let socksCredentials: LocalSocksCredentials
    }

    private var bridge: SocksTunnelBridge?
    private var transientConfigURL: URL?

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        do {
            guard let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol,
                  let rawID = tunnelProtocol.providerConfiguration?[AppConstants.providerProfileIDKey] as? String,
                  let profileID = UUID(uuidString: rawID) else {
                throw ClientError.missingProfile
            }
            let payload = try TunnelProfilePayload.decode(from: options)
                ?? SecureProfileStore.load(id: profileID)
            let prepared = try prepareCore(payload: payload)
            let settings = makeNetworkSettings(routeAddresses: prepared.routeAddresses)
            setTunnelNetworkSettings(settings) { [weak self] error in
                guard let self else { return }
                if let error {
                    self.stopCore()
                    completionHandler(error)
                    return
                }
                do {
                    try self.startCore(prepared)
                    completionHandler(nil)
                } catch {
                    self.stopCore()
                    completionHandler(error)
                }
            }
        } catch {
            completionHandler(error)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        stopCore()
        completionHandler()
    }

    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)? = nil
    ) {
        guard messageData == TunnelProviderMessage.trafficSnapshotRequest else {
            completionHandler?(nil)
            return
        }
        let snapshot = bridge?.currentSnapshot() ?? .zero
        completionHandler?(try? JSONEncoder().encode(snapshot))
    }

    private func prepareCore(payload: StoredProfilePayload) throws -> PreparedCore {
        let dataDirectory = try geoDirectory()
        guard let egressInterface = PhysicalEgressInterface.resolve() else {
            throw TunnelStartupError.egressInterfaceSelection
        }
        let newBridge = SocksTunnelBridge(
            packetFlow: packetFlow,
            outboundInterfaceBound: true,
            onUnexpectedExit: { [weak self] _ in
                self?.cancelTunnelWithError(TunnelRuntimeError.transportBridgeExited)
            }
        )
        let socksPort: Int
        do {
            guard let selectedPort = try SwiftyXray.getFreePorts(1).first else {
                throw ClientError.unsupportedConfiguration
            }
            socksPort = selectedPort
        } catch {
            throw TunnelStartupError.configurationConversion
        }
        let socksCredentials = LocalSocksCredentials(
            port: socksPort,
            username: UUID().uuidString.replacingOccurrences(of: "-", with: ""),
            password: UUID().uuidString.replacingOccurrences(of: "-", with: "")
                + UUID().uuidString.replacingOccurrences(of: "-", with: "")
        )
        let intermediate: XrayIntermediateConfig = switch payload.kind {
        case .xrayJSON: .json(payload.content)
        case .shareLink: .url(payload.content)
        }
        let built: [String: Any]
        do {
            let converter = XrayBridge(packetFlow: packetFlow)
            let converted = try converter.buildConfig(
                config: intermediate,
                sniffing: SniffingConfiguration(
                    destOverride: ["http", "tls", "quic"],
                    enabled: true,
                    routeOnly: false,
                    domainsExcluded: [],
                    metadataOnly: false
                )
            )
            built = try XraySocksInboundBuilder.replacingInbounds(
                in: converted,
                credentials: socksCredentials
            )
        } catch {
            throw TunnelStartupError.configurationConversion
        }

        let hardened: [String: Any]
        let serialized: Data
        do {
            hardened = try XrayConfigHardener.harden(
                built,
                egressInterface: egressInterface
            )
            serialized = try JSONSerialization.data(withJSONObject: hardened, options: [.sortedKeys])
        } catch {
            throw TunnelStartupError.configurationHardening
        }

        let routeAddresses: [TunnelIPAddress]
        let endpointHosts: [String]
        switch payload.kind {
        case .shareLink:
            if let host = ShareLinkEndpointExtractor.host(in: payload.content) {
                endpointHosts = [host]
            } else {
                endpointHosts = XrayOutboundEndpointExtractor.hosts(in: hardened)
            }
        case .xrayJSON:
            endpointHosts = XrayOutboundEndpointExtractor.hosts(in: hardened)
        }
        guard !endpointHosts.isEmpty else {
            throw TunnelStartupError.routeEndpointExtraction
        }

        do {
            let endpointAddresses = try TunnelRouteResolver.resolve(hosts: endpointHosts)
            let bootstrapAddresses = (try? TunnelRouteResolver.resolve(
                hosts: XrayConfigHardener.directBootstrapAddresses
            )) ?? []
            var seen = Set<TunnelIPAddress>()
            routeAddresses = (endpointAddresses + bootstrapAddresses).filter {
                seen.insert($0).inserted
            }
        } catch {
            throw TunnelStartupError.routeResolution
        }

        let configURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("client-xray-\(UUID().uuidString).json")
        do {
            try serialized.write(to: configURL, options: [.atomic, .completeFileProtectionUnlessOpen])
        } catch {
            throw TunnelStartupError.configurationPersistence
        }
        transientConfigURL = configURL

        return PreparedCore(
            bridge: newBridge,
            dataDirectory: dataDirectory,
            configURL: configURL,
            routeAddresses: routeAddresses,
            socksCredentials: socksCredentials
        )
    }

    private func startCore(_ prepared: PreparedCore) throws {
        do {
            try prepared.bridge.start(
                configURL: prepared.configURL,
                dataDirectory: prepared.dataDirectory,
                credentials: prepared.socksCredentials
            )
        } catch {
            throw TunnelStartupError.engineStart
        }
        bridge = prepared.bridge
        try? FileManager.default.removeItem(at: prepared.configURL)
        transientConfigURL = nil
    }

    private func stopCore() {
        bridge?.stop()
        bridge = nil
        if let transientConfigURL {
            try? FileManager.default.removeItem(at: transientConfigURL)
        }
        transientConfigURL = nil
    }

    private func geoDirectory() throws -> URL {
        guard let geoIP = Bundle.main.url(forResource: "geoip", withExtension: "dat", subdirectory: "Geo"),
              Bundle.main.url(forResource: "geosite", withExtension: "dat", subdirectory: "Geo") != nil else {
            throw ClientError.missingGeoData
        }
        return geoIP.deletingLastPathComponent()
    }

    private func makeNetworkSettings(
        routeAddresses: [TunnelIPAddress]
    ) -> NEPacketTunnelNetworkSettings {
        let remoteAddress = routeAddresses.first?.value ?? "127.0.0.1"
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)
        settings.mtu = 1360

        // Keep the interface address outside tun2proxy's 198.18.0.0/15
        // virtual-DNS pool so fake-IP replies always route back into the tunnel.
        let ipv4 = NEIPv4Settings(addresses: ["10.250.0.2"], subnetMasks: ["255.255.255.252"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        ipv4.excludedRoutes = routeAddresses.compactMap { address in
            guard address.family == .ipv4 else { return nil }
            return NEIPv4Route(destinationAddress: address.value, subnetMask: "255.255.255.255")
        }
        settings.ipv4Settings = ipv4

        let ipv6 = NEIPv6Settings(addresses: ["fd00:ce:cc::1"], networkPrefixLengths: [64])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        ipv6.excludedRoutes = routeAddresses.compactMap { address in
            guard address.family == .ipv6 else { return nil }
            return NEIPv6Route(
                destinationAddress: address.value,
                networkPrefixLength: NSNumber(value: 128)
            )
        }
        settings.ipv6Settings = ipv6

        // tun2proxy's virtual DNS maps names into its 198.18.0.0/15 pool and
        // later forwards the original hostname through SOCKS. Point iOS at
        // that in-tunnel resolver so DNS cannot bypass the packet flow.
        let dns = NEDNSSettings(servers: AppConstants.virtualDNSServers)
        dns.matchDomains = [""]
        dns.matchDomainsNoSearch = true
        settings.dnsSettings = dns
        return settings
    }
}
