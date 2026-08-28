//
// XrayBridge.swift
// SwiftyXrayKit
//
// Copyright © 2025 Dmitry Ulyanov
//
// Bridges NEPacketTunnelFlow ↔ XRay's built-in gVisor tun inbound.
// XRay is configured with a "tun" protocol inbound; its fd is one end of a
// SOCK_DGRAM socketpair so every read receives exactly one Darwin TUN packet.
// No hev or SOCKS5 layer is needed.
//
// Data flow:
//   packetFlow.readPackets → [4-byte AF header][IP packet] → socketpair fd[1]
//       → fd[0] → XRay gVisor → outbound proxy → remote
//   remote → outbound proxy → XRay gVisor → fd[0]
//       → fd[1] recv → [4-byte AF header][IP packet] → packetFlow.writePackets

import Foundation
import NetworkExtension
import Darwin

public enum XrayBridgeError: Error {
    case socketPairFailed
    case socketConfigurationFailed
    case invalidConfig
}

private final class UncheckedSendableBox<Value>: @unchecked Sendable {
    let value: Value

    init(_ value: Value) {
        self.value = value
    }
}

public final class XrayBridge: @unchecked Sendable {

    private weak var packetFlow: NEPacketTunnelFlow?
    private var swiftFd: Int32 = -1
    private var xrayFd: Int32 = -1
    private var isRunning = false

    private let statsLock = NSLock()
    private var _bytesReceived: Int64 = 0  // device ← remote (read thread)
    private var _bytesSent: Int64 = 0      // device → remote (packet flow)

    public init(packetFlow: NEPacketTunnelFlow) {
        self.packetFlow = packetFlow
    }

    deinit {
        if xrayFd >= 0 { Darwin.close(xrayFd) }
        if swiftFd >= 0 { Darwin.close(swiftFd) }
    }

    /// Starts XRay, building the config from `config` JSON.
    ///
    /// The kit injects the TUN inbound and optional sniffing, then calls
    /// `configTransform` (if provided) so you can mutate any part of the
    /// dictionary before it is written to `finalConfigPath` and run.
    ///
    /// - Parameters:
    ///   - config: Intermediate Xray JSON (outbounds, routing, etc. — no inbound needed).
    ///   - dataDir: Directory containing geo data files.
    ///   - finalConfigPath: Where the final JSON is written before running.
    ///   - sniffing: Optional sniffing injected into the TUN inbound.
    ///   - preset: Tuning preset to apply before run. Defaults to `.default`.
    ///   - configTransform: Optional closure receiving the kit-built config dictionary.
    ///                      Return a modified copy to customise anything before writing.
    ///   - traceHandle: Optional log sink for Xray lifecycle messages.
    public func start(
        config: XrayIntermediateConfig,
        dataDir: URL,
        finalConfigPath: URL,
        sniffing: SniffingConfiguration? = nil,
        preset: XrayTuningPreset = .default,
        configTransform: (([String: Any]) -> [String: Any])? = nil,
        traceHandle: ((String) -> Void)? = nil
    ) throws {
        let json: String
        switch config {
        case .json(let s): json = s
        case .url(let link): json = try SwiftyXray.xrayShareLinkToJson(url: link)
        }
        try openSocketPairAndApplyPreset(preset)
        var dict = try buildConfigDict(json: json, sniffing: sniffing)
        if let transform = configTransform { dict = transform(dict) }
        try writeAndRun(dict: dict, dataDir: dataDir, finalConfigPath: finalConfigPath, traceHandle: traceHandle)
    }

    /// Starts XRay with a fully pre-built config file — no patching applied.
    ///
    /// Use this when you want complete control over the Xray JSON.
    /// The kit only creates the socketpair and passes the fd to Xray before running.
    ///
    /// - Parameters:
    ///   - rawConfigPath: Path to your pre-built Xray config JSON.
    ///   - dataDir: Directory containing geo data files.
    ///   - preset: Tuning preset to apply before run. Defaults to `.default`.
    ///   - traceHandle: Optional log sink for Xray lifecycle messages.
    public func startWithRawConfig(
        rawConfigPath: URL,
        dataDir: URL,
        preset: XrayTuningPreset = .default,
        traceHandle: ((String) -> Void)? = nil
    ) throws {
        try openSocketPairAndApplyPreset(preset)
        try SwiftyXray.run(dataDir: dataDir.path, configPath: rawConfigPath.path, traceHandle: traceHandle)
        isRunning = true
        launchReadThread(fd: swiftFd)
        readFromPacketFlow()
    }

    /// Returns the config dictionary that `start(config:…)` would produce,
    /// without writing or running anything. Use to inspect or test the output.
    public func buildConfig(
        config: XrayIntermediateConfig,
        sniffing: SniffingConfiguration? = nil,
        configTransform: (([String: Any]) -> [String: Any])? = nil
    ) throws -> [String: Any] {
        let json: String
        switch config {
        case .json(let s): json = s
        case .url(let link): json = try SwiftyXray.xrayShareLinkToJson(url: link)
        }
        var dict = try buildConfigDict(json: json, sniffing: sniffing)
        if let transform = configTransform { dict = transform(dict) }
        return dict
    }

    /// Stops XRay and closes the socketpair.
    public func stop() {
        isRunning = false
        let x = xrayFd, s = swiftFd
        xrayFd = -1
        swiftFd = -1
        if x >= 0 { Darwin.close(x) }
        if s >= 0 { Darwin.close(s) }
        try? SwiftyXray.stop()
    }

    /// Returns bytes transferred since last call and resets counters.
    public func getAndClearStats() -> BytesTransferred {
        statsLock.lock()
        let r = _bytesReceived
        let s = _bytesSent
        _bytesReceived = 0
        _bytesSent = 0
        statsLock.unlock()
        return BytesTransferred(received: max(0, r), sent: max(0, s))
    }

    /// Returns cumulative counters for the current bridge session without
    /// resetting them.
    public func currentStats() -> BytesTransferred {
        statsLock.lock()
        let result = BytesTransferred(
            received: max(0, _bytesReceived),
            sent: max(0, _bytesSent)
        )
        statsLock.unlock()
        return result
    }

    // MARK: - Helpers

    private func openSocketPairAndApplyPreset(_ preset: XrayTuningPreset) throws {
        var fds: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds) == 0 else {
            throw XrayBridgeError.socketPairFailed
        }
        var noSigPipe: Int32 = 1
        guard setsockopt(
            fds[0],
            SOL_SOCKET,
            SO_NOSIGPIPE,
            &noSigPipe,
            socklen_t(MemoryLayout<Int32>.size)
        ) == 0,
        setsockopt(
            fds[1],
            SOL_SOCKET,
            SO_NOSIGPIPE,
            &noSigPipe,
            socklen_t(MemoryLayout<Int32>.size)
        ) == 0 else {
            Darwin.close(fds[0])
            Darwin.close(fds[1])
            throw XrayBridgeError.socketConfigurationFailed
        }
        xrayFd = fds[0]
        swiftFd = fds[1]
        SwiftyXray.setTunFd(xrayFd)
        preset.apply()
    }

    private func buildConfigDict(json: String, sniffing: SniffingConfiguration?) throws -> [String: Any] {
        guard let data = json.data(using: .utf8),
              var config = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw XrayBridgeError.invalidConfig
        }
        var inbound: [String: Any] = [
            "protocol": "tun",
            "settings": ["name": "utun", "MTU": 1360],
            "tag": "in_proxy"
        ]
        if let sniffing {
            inbound["sniffing"] = [
                "destOverride": sniffing.destOverride,
                "enabled": sniffing.enabled,
                "routeOnly": sniffing.routeOnly,
                "metadataOnly": sniffing.metadataOnly,
                "domainsExcluded": sniffing.domainsExcluded
            ]
        }
        config["inbounds"] = [inbound]
        return config
    }

    private func writeAndRun(
        dict: [String: Any],
        dataDir: URL,
        finalConfigPath: URL,
        traceHandle: ((String) -> Void)?
    ) throws {
        let data = try JSONSerialization.data(withJSONObject: dict, options: .prettyPrinted)
        let json = String(decoding: data, as: UTF8.self)
        traceHandle?("###XrayBridge final config: \(json)")
        try json.write(to: finalConfigPath, atomically: true, encoding: .utf8)
        try SwiftyXray.run(dataDir: dataDir.path, configPath: finalConfigPath.path, traceHandle: traceHandle)
        isRunning = true
        launchReadThread(fd: swiftFd)
        readFromPacketFlow()
    }

    // MARK: - Threads

    // Reads complete Darwin TUN datagrams from XRay and forwards their IP payloads.
    // Exits when recv returns 0 or an error (fd closed by stop()).
    private func launchReadThread(fd: Int32) {
        guard let flow = packetFlow else { return }
        let flowBox = UncheckedSendableBox(flow)
        Thread.detachNewThread { [weak self, flowBox] in
            let maxDatagram = XrayTunDatagramCodec.maximumDatagramLength
            let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: maxDatagram)
            defer { buf.deallocate() }

            var keepRunning = true
            while keepRunning {
                autoreleasepool {
                    let received = Darwin.recv(fd, buf, maxDatagram, 0)
                    if received < 0, errno == EINTR { return }
                    guard received > 0 else {
                        keepRunning = false
                        return
                    }
                    let frame = Data(bytes: buf, count: received)
                    guard let decoded = XrayTunDatagramCodec.decode(frame) else { return }

                    if let self {
                        self.statsLock.lock()
                        self._bytesReceived += Int64(decoded.packet.count)
                        self.statsLock.unlock()
                    }
                    flowBox.value.writePackets(
                        [decoded.packet],
                        withProtocols: [decoded.protocolNumber]
                    )
                }
            }
        }
    }

    // Reads packets from the system via packetFlow and forwards them to XRay (fd[1]).
    // One send corresponds to one [4-byte big-endian AF][raw IP packet] datagram.
    private func readFromPacketFlow() {
        guard isRunning, let packetFlow else { return }
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self, self.isRunning, self.swiftFd >= 0 else { return }
            let fd = self.swiftFd
            var writeFailed = false
            for (packet, proto) in zip(packets, protocols) {
                guard let frame = XrayTunDatagramCodec.encode(
                    packet: packet,
                    protocolNumber: proto
                ) else {
                    continue
                }
                let sent = frame.withUnsafeBytes {
                    Self.sendDatagram(fd: fd, bytes: $0)
                }
                guard sent else {
                    writeFailed = true
                    break
                }
                self.statsLock.lock()
                self._bytesSent += Int64(packet.count)
                self.statsLock.unlock()
            }
            guard !writeFailed else {
                self.stop()
                return
            }
            self.readFromPacketFlow()
        }
    }

    private static func sendDatagram(fd: Int32, bytes: UnsafeRawBufferPointer) -> Bool {
        guard let baseAddress = bytes.baseAddress else { return bytes.isEmpty }
        while true {
            let written = Darwin.send(fd, baseAddress, bytes.count, 0)
            if written == bytes.count {
                return true
            }
            if written < 0, errno == EINTR {
                continue
            }
            return false
        }
    }
}
