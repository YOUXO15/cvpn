import NetworkExtension
import SwiftUI

struct RootView: View {
    @EnvironmentObject private var profiles: ProfileRepository
    @EnvironmentObject private var vpn: VPNController
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    @State private var showsImporter = false
    @State private var showsSecurity = false
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 20) {
                    statusCard
                    profileSection
                    privacyNote
                }
                .padding(.horizontal, 20)
                .padding(.bottom, 32)
            }
            .background(Color(uiColor: .systemGroupedBackground))
            .navigationTitle("VPN Client")
            .toolbar {
                ToolbarItemGroup(placement: .navigationBarTrailing) {
                    Button {
                        showsSecurity = true
                    } label: {
                        Image(systemName: "lock.shield")
                    }
                    .accessibilityLabel("Защита конфигураций")

                    Button {
                        showsImporter = true
                    } label: {
                        Image(systemName: "plus")
                    }
                    .accessibilityLabel("Добавить VPN-профиль")
                }
            }
            .sheet(isPresented: $showsImporter) {
                ImportProfileView()
                    .environmentObject(profiles)
            }
            .sheet(isPresented: $showsSecurity) {
                SecurityDetailsView()
            }
            .alert("Не удалось выполнить действие", isPresented: errorBinding) {
                Button("Понятно", role: .cancel) { errorMessage = nil }
            } message: {
                Text(errorMessage ?? "Неизвестная ошибка")
            }
            .onChange(of: vpn.lastDisconnectMessage) { message in
                guard let message else { return }
                errorMessage = message
                vpn.clearLastDisconnectMessage()
            }
        }
    }

    private var statusCard: some View {
        VStack(spacing: 18) {
            ZStack {
                Circle()
                    .fill(.white.opacity(0.09))
                    .frame(width: 116, height: 116)
                Image(systemName: statusSymbol)
                    .font(.system(size: 48, weight: .semibold))
                    .foregroundStyle(statusColor)
            }

            VStack(spacing: 6) {
                Text(vpn.statusTitle)
                    .font(.title2.weight(.semibold))
                Text(connectionSubtitle)
                    .font(.subheadline)
                    .foregroundStyle(.white.opacity(0.7))
                    .multilineTextAlignment(.center)
                    .lineLimit(dynamicTypeSize.isAccessibilitySize ? nil : 2)

                if vpn.isConnected {
                    VStack(spacing: 7) {
                        HStack(spacing: 18) {
                            trafficLabel(
                                systemImage: "arrow.up",
                                title: formattedBytes(vpn.traffic.sentBytes),
                                accessibilityLabel: "Отправлено"
                            )
                            trafficLabel(
                                systemImage: "arrow.down",
                                title: formattedBytes(vpn.traffic.receivedBytes),
                                accessibilityLabel: "Получено"
                            )
                        }
                        Text(trafficDiagnostic)
                            .font(.caption2)
                            .foregroundStyle(.white.opacity(0.72))
                    }
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.white.opacity(0.82))
                }
            }

            Button(action: toggleConnection) {
                HStack(spacing: 10) {
                    if vpn.isBusy {
                        ProgressView()
                            .tint(ClientTheme.deepNavy)
                    } else {
                        Image(systemName: vpn.isConnected ? "stop.fill" : "power")
                    }
                    Text(vpn.isConnected ? "Отключить" : "Подключить")
                        .fontWeight(.semibold)
                }
                .frame(maxWidth: .infinity, minHeight: 52)
                .background(ClientTheme.action, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                .foregroundStyle(ClientTheme.deepNavy)
            }
            .buttonStyle(.plain)
            .disabled(vpn.isBusy)
            .accessibilityHint(vpn.isConnected ? "Остановит VPN-туннель" : "Запустит выбранный VPN-профиль")
        }
        .padding(24)
        .background(
            LinearGradient(
                colors: [ClientTheme.deepNavy, ClientTheme.navy],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            ),
            in: RoundedRectangle(cornerRadius: 28, style: .continuous)
        )
        .foregroundStyle(.white)
        .accessibilityElement(children: .contain)
    }

    private var profileSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Профили")
                    .font(.headline)
                Spacer()
                Text("\(profiles.profiles.count)")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }

            if profiles.profiles.isEmpty {
                Button {
                    showsImporter = true
                } label: {
                    VStack(spacing: 12) {
                        Image(systemName: "link.badge.plus")
                            .font(.system(size: 28))
                        Text("Добавить защищённую ссылку")
                            .font(.headline)
                        Text("Ссылка не сохраняется после импорта. Конфигурация хранится в Keychain.")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    .frame(maxWidth: .infinity, minHeight: 154)
                    .padding()
                    .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 20))
                }
                .buttonStyle(.plain)
            } else {
                VStack(spacing: 10) {
                    ForEach(profiles.profiles) { profile in
                        profileRow(profile)
                    }
                }
            }
        }
    }

    private func profileRow(_ profile: ProfileSummary) -> some View {
        HStack(spacing: 0) {
            Button {
                profiles.select(profile.id)
            } label: {
                HStack(spacing: 14) {
                    Image(systemName: profiles.selectedProfileID == profile.id ? "checkmark.circle.fill" : "circle")
                        .font(.title3)
                        .foregroundStyle(profiles.selectedProfileID == profile.id ? ClientTheme.accent : .secondary)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(profile.name)
                            .font(.body.weight(.medium))
                            .foregroundStyle(.primary)
                            .lineLimit(1)
                        Text(profile.sourceHost ?? "Добавлен вручную")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                    Spacer()
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityValue(profiles.selectedProfileID == profile.id ? "Выбран" : "Не выбран")

            Menu {
                Button("Удалить", systemImage: "trash", role: .destructive) {
                    delete(profile)
                }
            } label: {
                Image(systemName: "ellipsis")
                    .frame(width: 44, height: 44)
                    .contentShape(Rectangle())
            }
            .accessibilityLabel("Действия с профилем \(profile.name)")
        }
        .padding(.leading, 16)
        .padding(.trailing, 8)
        .frame(minHeight: 68)
        .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 18))
    }

    private var privacyNote: some View {
        Label {
            Text("Приложение не записывает VPN-ссылки и содержимое конфигураций в журналы.")
        } icon: {
            Image(systemName: "eye.slash")
        }
        .font(.footnote)
        .foregroundStyle(.secondary)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 4)
    }

    private var errorBinding: Binding<Bool> {
        Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
    }

    private var statusSymbol: String {
        switch vpn.status {
        case .connected: return "shield.checkered"
        case .connecting, .reasserting: return "shield.lefthalf.filled"
        case .disconnecting: return "shield.slash"
        default: return "shield"
        }
    }

    private var statusColor: Color {
        vpn.isConnected ? ClientTheme.action : .white
    }

    private var connectionSubtitle: String {
        if let selected = profiles.selectedProfile {
            return selected.name
        }
        return "Добавьте профиль, чтобы начать"
    }

    private func trafficLabel(
        systemImage: String,
        title: String,
        accessibilityLabel: String
    ) -> some View {
        Label(title, systemImage: systemImage)
            .accessibilityLabel("\(accessibilityLabel): \(title)")
    }

    private func formattedBytes(_ value: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: max(0, value), countStyle: .file)
    }

    private var trafficDiagnostic: String {
        guard vpn.traffic.transportReady else {
            return "TUN-мост не готов"
        }
        guard vpn.traffic.outboundInterfaceBound else {
            return "Исходящий интерфейс не привязан"
        }
        if vpn.traffic.sentPackets == 0 {
            return "TUN-мост готов · ожидаем трафик"
        }
        if vpn.traffic.receivedPackets == 0 {
            return "Пакеты отправляются · ответа пока нет"
        }
        return "Трафик проходит в обе стороны"
    }

    private func toggleConnection() {
        if vpn.isConnected {
            vpn.disconnect()
            return
        }
        guard let profile = profiles.selectedProfile else {
            showsImporter = true
            return
        }
        Task {
            do {
                try await vpn.connect(profile: profile)
            } catch {
                errorMessage = (error as? LocalizedError)?.errorDescription ?? "Подключение не удалось."
            }
        }
    }

    private func delete(_ profile: ProfileSummary) {
        guard !(vpn.isConnected && vpn.activeProfileID == profile.id) else {
            errorMessage = "Сначала отключите активный профиль."
            return
        }
        do {
            try profiles.delete(profile)
        } catch {
            errorMessage = (error as? LocalizedError)?.errorDescription ?? "Удаление не удалось."
        }
    }
}
