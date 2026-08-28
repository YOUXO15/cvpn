import Foundation
@preconcurrency import NetworkExtension

private final class NotificationObserverToken: @unchecked Sendable {
    private let value: NSObjectProtocol

    init(_ value: NSObjectProtocol) {
        self.value = value
    }

    deinit {
        NotificationCenter.default.removeObserver(value)
    }
}

@MainActor
final class VPNController: ObservableObject {
    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var activeProfileID: UUID?
    @Published private(set) var lastDisconnectMessage: String?
    @Published private(set) var traffic: TunnelTrafficSnapshot = .zero

    private var manager: NETunnelProviderManager?
    private var observer: NotificationObserverToken?
    private var intentionalDisconnect = false
    private var connectionAttemptPending = false
    private var trafficPollingTask: Task<Void, Never>?

    init() {
        let token = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let connection = notification.object as? NEVPNConnection else { return }
            Task { @MainActor [weak self] in
                guard let self, connection === self.manager?.connection else { return }
                self.handleStatusChange(connection)
            }
        }
        observer = NotificationObserverToken(token)
        Task { await load() }
    }

    func load() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            manager = managers.first { manager in
                (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                    == AppConstants.tunnelBundleIdentifier
            }
            status = manager?.connection.status ?? .disconnected
            if let raw = (manager?.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerConfiguration?[AppConstants.providerProfileIDKey] as? String {
                activeProfileID = UUID(uuidString: raw)
            }
            if status == .connected {
                startTrafficPolling(reset: false)
            }
        } catch {
            manager = nil
            status = .invalid
        }
    }

    func connect(profile: ProfileSummary) async throws {
        intentionalDisconnect = false
        lastDisconnectMessage = nil
        traffic = .zero
        let payload = try SecureProfileStore.load(id: profile.id)
        let payloadData = try TunnelProfilePayload.encode(payload)
        let selectedManager = manager ?? makeManager()
        guard let tunnelProtocol = selectedManager.protocolConfiguration as? NETunnelProviderProtocol else {
            throw ClientError.tunnelConfigurationFailed
        }
        tunnelProtocol.providerConfiguration = [
            AppConstants.providerProfileIDKey: profile.id.uuidString
        ]
        tunnelProtocol.enforceRoutes = true
        tunnelProtocol.serverAddress = profile.sourceHost ?? "VPN Client"
        tunnelProtocol.disconnectOnSleep = false
        selectedManager.protocolConfiguration = tunnelProtocol
        selectedManager.localizedDescription = "VPN Client"
        selectedManager.isEnabled = true

        try await selectedManager.saveToPreferences()
        try await selectedManager.loadFromPreferences()
        manager = selectedManager
        activeProfileID = profile.id
        connectionAttemptPending = true
        do {
            try selectedManager.connection.startVPNTunnel(options: [
                AppConstants.providerProfilePayloadKey: payloadData as NSData
            ])
        } catch {
            connectionAttemptPending = false
            throw error
        }
    }

    func disconnect() {
        intentionalDisconnect = true
        connectionAttemptPending = false
        stopTrafficPolling()
        manager?.connection.stopVPNTunnel()
    }

    func clearLastDisconnectMessage() {
        lastDisconnectMessage = nil
    }

    var isConnected: Bool { status == .connected }
    var isBusy: Bool { [.connecting, .disconnecting, .reasserting].contains(status) }

    var statusTitle: String {
        switch status {
        case .connected: return "Защищено"
        case .connecting: return "Подключаем"
        case .disconnecting: return "Отключаем"
        case .reasserting: return "Восстанавливаем"
        case .invalid: return "Нужна настройка"
        default: return "Не подключено"
        }
    }

    private func makeManager() -> NETunnelProviderManager {
        let result = NETunnelProviderManager()
        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.providerBundleIdentifier = AppConstants.tunnelBundleIdentifier
        tunnelProtocol.serverAddress = "VPN Client"
        result.protocolConfiguration = tunnelProtocol
        return result
    }

    private func handleStatusChange(_ connection: NEVPNConnection) {
        let previousStatus = status
        status = connection.status

        if connection.status == .connected {
            connectionAttemptPending = false
            startTrafficPolling(reset: true)
            return
        }

        guard [.disconnected, .invalid].contains(connection.status) else { return }
        stopTrafficPolling()
        if intentionalDisconnect {
            intentionalDisconnect = false
            connectionAttemptPending = false
            return
        }
        guard connectionAttemptPending
                || [.connecting, .connected, .reasserting].contains(previousStatus) else { return }
        connectionAttemptPending = false

        connection.fetchLastDisconnectError { [weak self] error in
            let message = VPNDisconnectDiagnostic.message(for: error)
            Task { @MainActor [weak self] in
                self?.lastDisconnectMessage = message
            }
        }
    }

    private func startTrafficPolling(reset: Bool) {
        stopTrafficPolling()
        if reset { traffic = .zero }
        trafficPollingTask = Task { [weak self] in
            while !Task.isCancelled {
                self?.requestTrafficSnapshot()
                do {
                    try await Task.sleep(for: .seconds(1))
                } catch {
                    return
                }
            }
        }
    }

    private func stopTrafficPolling() {
        trafficPollingTask?.cancel()
        trafficPollingTask = nil
    }

    private func requestTrafficSnapshot() {
        guard status == .connected,
              let session = manager?.connection as? NETunnelProviderSession else { return }
        do {
            try session.sendProviderMessage(TunnelProviderMessage.trafficSnapshotRequest) { [weak self] data in
                guard let data,
                      let snapshot = try? JSONDecoder().decode(
                        TunnelTrafficSnapshot.self,
                        from: data
                      ) else { return }
                Task { @MainActor [weak self] in
                    guard let self, self.status == .connected else { return }
                    self.traffic = snapshot
                }
            }
        } catch {
            // A missed sample must not interrupt the tunnel or expose provider details.
        }
    }
}

enum VPNDisconnectDiagnostic {
    static func message(for error: Error?) -> String {
        guard let error else {
            return "iOS не запустила Packet Tunnel. Проверь, что программа подписи сохранила разрешение Network Extension и подписала встроенное расширение отдельным подходящим профилем."
        }

        let nsError = error as NSError
        if nsError.domain == TunnelStartupError.errorDomain,
           let stage = TunnelStartupError(rawValue: nsError.code) {
            switch stage {
            case .configurationConversion:
                return "Формат выбранного профиля не удалось преобразовать для VPN-движка (этап 1). Секретные параметры скрыты."
            case .configurationHardening:
                return "Профиль не прошёл безопасную подготовку перед запуском (этап 2). Секретные параметры скрыты."
            case .configurationPersistence:
                return "iOS не позволила временно подготовить конфигурацию туннеля (этап 3)."
            case .engineStart:
                return "VPN-движок отклонил подготовленную конфигурацию при запуске (этап 4). Секретные параметры скрыты."
            case .routeEndpointExtraction:
                return "Не удалось определить адрес VPN-сервера из профиля (этап 5). Секретные параметры скрыты."
            case .routeResolution:
                return "Не удалось определить сетевой маршрут до VPN-сервера (этап 6). Секретные параметры скрыты."
            }
        }

        guard nsError.domain == NEVPNConnectionErrorDomain,
              let connectionError = NEVPNConnectionError(rawValue: nsError.code) else {
            return "Туннель завершился внутренней ошибкой (\(nsError.domain), код \(nsError.code)). Содержимое VPN-профиля скрыто."
        }

        switch connectionError {
        case .pluginDisabled:
            return "iOS не разрешила запустить Packet Tunnel. Проверь, что после подписи и приложение, и расширение имеют разрешение Network Extension (код \(nsError.code))."
        case .pluginFailed:
            return "Расширение Packet Tunnel завершилось при запуске. Нужен подписанный IPA для проверки его разрешений; приложение не раскрывает содержимое VPN-профиля (код \(nsError.code))."
        case .configurationFailed, .configurationNotFound:
            return "iOS не приняла конфигурацию Packet Tunnel. Обычно это означает изменённый bundle ID расширения или неподходящий provisioning profile (код \(nsError.code))."
        case .noNetworkAvailable:
            return "На устройстве нет доступного подключения к интернету (код \(nsError.code))."
        case .serverAddressResolutionFailed:
            return "Не удалось определить адрес VPN-сервера (код \(nsError.code))."
        case .serverNotResponding, .serverDead, .serverDisconnected:
            return "VPN-сервер не ответил или разорвал соединение (код \(nsError.code))."
        case .authenticationFailed:
            return "VPN-сервер отклонил параметры профиля (код \(nsError.code))."
        default:
            return "VPN отключился с системной ошибкой (код \(nsError.code))."
        }
    }
}
