import SwiftUI

struct SecurityDetailsView: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                Section("Сетевая защита") {
                    securityRow(
                        icon: "checkmark.seal",
                        title: "TLS и системная проверка сертификата",
                        detail: "Небезопасные HTTP-ссылки отклоняются."
                    )
                    securityRow(
                        icon: "pin",
                        title: "SPKI pinning",
                        detail: "Ключ сервера сверяется с закреплённым ключом внутри приложения."
                    )
                    securityRow(
                        icon: "signature",
                        title: "Подписанные конфигурации",
                        detail: "Даже после загрузки JSON проверяется отдельная подпись Ed25519."
                    )
                }

                Section("На устройстве") {
                    securityRow(
                        icon: "key.fill",
                        title: "Keychain",
                        detail: "VPN-учётные данные доступны только приложению и его tunnel extension."
                    )
                    securityRow(
                        icon: "doc.text.magnifyingglass",
                        title: "Без секретов в логах",
                        detail: "Ссылки, UUID и JSON не передаются в диагностические сообщения."
                    )
                }

                Section {
                    Text("Pinning защищает от подмены TLS-сертификата, но не делает взломанный или jailbroken iPhone доверенным устройством. Для таких устройств абсолютной защиты клиентского JSON не существует.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Защита")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Готово") { dismiss() }
                }
            }
        }
    }

    private func securityRow(icon: String, title: String, detail: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .foregroundStyle(ClientTheme.accent)
                .frame(width: 24, height: 24)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.body.weight(.medium))
                Text(detail).font(.subheadline).foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}

