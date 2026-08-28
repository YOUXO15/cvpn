import Darwin
import Dispatch
import Foundation
import NetworkExtension
import SwiftyXrayKit
import Tun2ProxyShim

enum SocksTunnelBridgeError: Error {
    case socketPairFailed
    case socketConfigurationFailed
    case proxyStartFailed
}

private final class SendablePacketFlowBox: @unchecked Sendable {
    let value: NEPacketTunnelFlow

    init(_ value: NEPacketTunnelFlow) {
        self.value = value
    }
}

final class SocksTunnelBridge: @unchecked Sendable {
    private static let mtu: UInt16 = 1_360

    private weak var packetFlow: NEPacketTunnelFlow?
    private let onUnexpectedExit: (Int32) -> Void
    private let statsLock = NSLock()
    private let stateLock = NSLock()
    private var swiftFd: Int32 = -1
    private var proxyFd: Int32 = -1
    private var running = false
    private var proxyExit = DispatchSemaphore(value: 0)
    private var sentBytes: Int64 = 0
    private var receivedBytes: Int64 = 0
    private var sentPackets: Int64 = 0
    private var receivedPackets: Int64 = 0

    init(
        packetFlow: NEPacketTunnelFlow,
        onUnexpectedExit: @escaping (Int32) -> Void
    ) {
        self.packetFlow = packetFlow
        self.onUnexpectedExit = onUnexpectedExit
    }

    deinit {
        stop()
    }

    func start(
        configURL: URL,
        dataDirectory: URL,
        credentials: LocalSocksCredentials
    ) throws {
        try openSocketPair()
        XrayTuningPreset.mobile.apply()
        do {
            try SwiftyXray.run(
                dataDir: dataDirectory.path,
                configPath: configURL.path,
                traceHandle: nil
            )
        } catch {
            closeSocketPair()
            throw error
        }

        proxyExit = DispatchSemaphore(value: 0)
        let fd = proxyFd
        let command = Self.command(fd: fd, credentials: credentials)
        let exitSignal = proxyExit
        Thread.detachNewThread { [weak self] in
            let exitCode = command.withCString { pointer in
                TunnelProxyRun(pointer, Self.mtu, true)
            }
            self?.proxyDidExit(fd: fd, exitCode: exitCode)
            exitSignal.signal()
        }

        let deadline = Date().addingTimeInterval(1)
        while !TunnelProxyIsRunning(), Date() < deadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        guard TunnelProxyIsRunning() else {
            try? SwiftyXray.stop()
            closeSocketPair()
            throw SocksTunnelBridgeError.proxyStartFailed
        }
        guard proxyExit.wait(timeout: .now() + .milliseconds(100)) == .timedOut,
              TunnelProxyIsRunning() else {
            try? SwiftyXray.stop()
            closeSocketPair()
            throw SocksTunnelBridgeError.proxyStartFailed
        }

        stateLock.lock()
        running = true
        stateLock.unlock()
        launchReadThread(fd: swiftFd)
        readFromPacketFlow()
    }

    func stop() {
        stateLock.lock()
        let wasRunning = running
        running = false
        stateLock.unlock()

        if wasRunning || TunnelProxyIsRunning() {
            _ = TunnelProxyStop()
            _ = proxyExit.wait(timeout: .now() + 1)
        }
        closeSocketPair()
        try? SwiftyXray.stop()
    }

    func currentSnapshot() -> TunnelTrafficSnapshot {
        stateLock.lock()
        let ready = running && TunnelProxyIsRunning()
        stateLock.unlock()
        statsLock.lock()
        let result = TunnelTrafficSnapshot(
            sentBytes: max(0, sentBytes),
            receivedBytes: max(0, receivedBytes),
            sentPackets: max(0, sentPackets),
            receivedPackets: max(0, receivedPackets),
            transportReady: ready
        )
        statsLock.unlock()
        return result
    }

    private static func command(
        fd: Int32,
        credentials: LocalSocksCredentials
    ) -> String {
        let user = credentials.username.addingPercentEncoding(
            withAllowedCharacters: .urlUserAllowed
        ) ?? credentials.username
        let password = credentials.password.addingPercentEncoding(
            withAllowedCharacters: .urlPasswordAllowed
        ) ?? credentials.password
        return [
            "tunnel-proxy",
            "--tun-fd", String(fd),
            "--close-fd-on-drop", "false",
            "--proxy", "socks5://\(user):\(password)@127.0.0.1:\(credentials.port)",
            "--dns", "virtual",
            "--ipv6-enabled",
            "--tcp-mss", "1320",
            "--max-sessions", "512",
            "--verbosity", "off"
        ].joined(separator: " ")
    }

    private func openSocketPair() throws {
        var fds: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds) == 0 else {
            throw SocksTunnelBridgeError.socketPairFailed
        }
        var noSigPipe: Int32 = 1
        guard setsockopt(
            fds[0], SOL_SOCKET, SO_NOSIGPIPE,
            &noSigPipe, socklen_t(MemoryLayout<Int32>.size)
        ) == 0,
        setsockopt(
            fds[1], SOL_SOCKET, SO_NOSIGPIPE,
            &noSigPipe, socklen_t(MemoryLayout<Int32>.size)
        ) == 0 else {
            Darwin.close(fds[0])
            Darwin.close(fds[1])
            throw SocksTunnelBridgeError.socketConfigurationFailed
        }
        proxyFd = fds[0]
        swiftFd = fds[1]
    }

    private func closeSocketPair() {
        stateLock.lock()
        let proxy = proxyFd
        let swift = swiftFd
        proxyFd = -1
        swiftFd = -1
        stateLock.unlock()
        if proxy >= 0 { Darwin.close(proxy) }
        if swift >= 0 { Darwin.close(swift) }
    }

    private func proxyDidExit(fd: Int32, exitCode: Int32) {
        stateLock.lock()
        let shouldClose = proxyFd == fd
        let unexpected = running
        running = false
        if shouldClose {
            proxyFd = -1
        }
        stateLock.unlock()
        if shouldClose {
            Darwin.close(fd)
        }
        if unexpected {
            onUnexpectedExit(exitCode)
        }
    }

    private func isRunning() -> Bool {
        stateLock.lock()
        let result = running
        stateLock.unlock()
        return result
    }

    private func launchReadThread(fd: Int32) {
        guard let packetFlow else { return }
        let flow = SendablePacketFlowBox(packetFlow)
        Thread.detachNewThread { [weak self, flow] in
            let capacity = XrayTunDatagramCodec.maximumDatagramLength
            let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
            defer { buffer.deallocate() }

            while self?.isRunning() == true {
                let count = Darwin.recv(fd, buffer, capacity, 0)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { return }
                let frame = Data(bytes: buffer, count: count)
                guard let decoded = XrayTunDatagramCodec.decode(frame) else { continue }
                if let self {
                    self.statsLock.lock()
                    self.receivedBytes += Int64(decoded.packet.count)
                    self.receivedPackets += 1
                    self.statsLock.unlock()
                }
                flow.value.writePackets(
                    [decoded.packet],
                    withProtocols: [decoded.protocolNumber]
                )
            }
        }
    }

    private func readFromPacketFlow() {
        guard isRunning(), let packetFlow else { return }
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self, self.isRunning() else { return }
            self.stateLock.lock()
            let fd = self.swiftFd
            self.stateLock.unlock()
            guard fd >= 0 else { return }

            for (packet, protocolNumber) in zip(packets, protocols) {
                guard let frame = XrayTunDatagramCodec.encode(
                    packet: packet,
                    protocolNumber: protocolNumber
                ) else { continue }
                let sent = frame.withUnsafeBytes { bytes -> Bool in
                    guard let base = bytes.baseAddress else { return false }
                    while true {
                        let result = Darwin.send(fd, base, bytes.count, 0)
                        if result == bytes.count { return true }
                        if result < 0, errno == EINTR { continue }
                        return false
                    }
                }
                guard sent else {
                    self.stop()
                    return
                }
                self.statsLock.lock()
                self.sentBytes += Int64(packet.count)
                self.sentPackets += 1
                self.statsLock.unlock()
            }
            self.readFromPacketFlow()
        }
    }
}
