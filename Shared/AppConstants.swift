import Foundation

enum AppConstants {
    static let appGroupIdentifier = "group.com.example.tunnelclient"
    static let defaultTunnelBundleIdentifier = "com.example.tunnelclient.PacketTunnel"
    static var tunnelBundleIdentifier: String {
        EmbeddedTunnelBundleLocator.resolve()
    }
    static let profileMetadataKey = "secure-profile-metadata-v1"
    static let keychainService = "com.example.tunnelclient.profile"
    static let providerProfileIDKey = "profileID"
    static let providerProfilePayloadKey = "profilePayload"
    static let maximumProfilesPerImport = 50
}

enum EmbeddedTunnelBundleLocator {
    static let packetTunnelExtensionPoint = "com.apple.networkextension.packet-tunnel"

    struct Candidate: Equatable {
        let bundleIdentifier: String
        let extensionPointIdentifier: String
    }

    static func selectIdentifier(
        from candidates: [Candidate],
        fallback: String
    ) -> String {
        candidates.first {
            $0.extensionPointIdentifier == packetTunnelExtensionPoint
                && !$0.bundleIdentifier.isEmpty
        }?.bundleIdentifier ?? fallback
    }

    static func resolve(in appBundle: Bundle = .main) -> String {
        let fallback = appBundle.bundleIdentifier.map { "\($0).PacketTunnel" }
            ?? AppConstants.defaultTunnelBundleIdentifier
        guard let pluginsURL = appBundle.builtInPlugInsURL,
              let pluginURLs = try? FileManager.default.contentsOfDirectory(
                  at: pluginsURL,
                  includingPropertiesForKeys: nil,
                  options: [.skipsHiddenFiles]
              ) else {
            return fallback
        }

        let candidates = pluginURLs.compactMap { url -> Candidate? in
            guard url.pathExtension == "appex",
                  let pluginBundle = Bundle(url: url),
                  let bundleIdentifier = pluginBundle.bundleIdentifier,
                  let extensionInfo = pluginBundle.infoDictionary?["NSExtension"] as? [String: Any],
                  let extensionPoint = extensionInfo["NSExtensionPointIdentifier"] as? String else {
                return nil
            }
            return Candidate(
                bundleIdentifier: bundleIdentifier,
                extensionPointIdentifier: extensionPoint
            )
        }

        return selectIdentifier(from: candidates, fallback: fallback)
    }
}

enum ClientError: LocalizedError, Equatable {
    case invalidLink
    case untrustedHost
    case pinMismatch
    case invalidServerResponse
    case responseTooLarge
    case unsignedConfiguration
    case invalidSignature
    case expiredConfiguration
    case unsupportedConfiguration
    case secureStorageFailure
    case missingProfile
    case missingGeoData
    case tunnelConfigurationFailed

    var errorDescription: String? {
        switch self {
        case .invalidLink:
            return "Ссылка имеет неподдерживаемый формат."
        case .untrustedHost:
            return "Этот сервер не включён в защищённый список приложения."
        case .pinMismatch:
            return "Подлинность сервера подтвердить не удалось. Импорт остановлен."
        case .invalidServerResponse:
            return "Сервер вернул некорректный ответ."
        case .responseTooLarge:
            return "Ответ сервера слишком большой."
        case .unsignedConfiguration:
            return "Конфигурация не имеет обязательной цифровой подписи."
        case .invalidSignature:
            return "Цифровая подпись конфигурации недействительна."
        case .expiredConfiguration:
            return "Срок действия конфигурации истёк."
        case .unsupportedConfiguration:
            return "Формат конфигурации пока не поддерживается."
        case .secureStorageFailure:
            return "Не удалось сохранить конфигурацию в защищённом хранилище."
        case .missingProfile:
            return "Выбранный профиль не найден."
        case .missingGeoData:
            return "В сборке отсутствуют geoip.dat или geosite.dat."
        case .tunnelConfigurationFailed:
            return "Не удалось подготовить VPN-туннель."
        }
    }
}

enum TunnelStartupError: Int, Error, CustomNSError {
    static let errorDomain = "com.example.tunnelclient.tunnel.startup"

    case configurationConversion = 1
    case configurationHardening = 2
    case configurationPersistence = 3
    case engineStart = 4
    case routeEndpointExtraction = 5
    case routeResolution = 6

    var errorCode: Int { rawValue }

    var errorUserInfo: [String: Any] { [:] }
}
