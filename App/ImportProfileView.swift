import SwiftUI

struct ImportProfileView: View {
    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject private var profiles: ProfileRepository

    @State private var link = ""
    @State private var revealsLink = false
    @State private var isImporting = false
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    HStack(alignment: .firstTextBaseline, spacing: 10) {
                        Group {
                            if revealsLink {
                                TextField("https://… или vless://…", text: $link, axis: .vertical)
                            } else {
                                SecureField("https://… или vless://…", text: $link)
                            }
                        }
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .textContentType(.URL)
                        .privacySensitive()

                        Button {
                            revealsLink.toggle()
                        } label: {
                            Image(systemName: revealsLink ? "eye.slash" : "eye")
                                .frame(width: 44, height: 44)
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel(revealsLink ? "Скрыть ссылку" : "Показать ссылку")
                    }

                    PasteButton(payloadType: String.self) { pastedValues in
                        guard let pasted = pastedValues.first?
                            .trimmingCharacters(in: .whitespacesAndNewlines),
                              !pasted.isEmpty else { return }
                        link = pasted
                        errorMessage = nil
                    }
                    .accessibilityLabel("Вставить ссылку из буфера")
                } header: {
                    Text("VPN-ссылка")
                } footer: {
                    Text("Ссылки подписки загружаются только через защищённое соединение с закреплённым сервером. Подписанные конфигурации дополнительно проверяются цифровой подписью.")
                }

                Section("Что будет сохранено") {
                    Label("Конфигурация — в системном Keychain", systemImage: "key")
                    Label("Название профиля — в общем контейнере приложения", systemImage: "tag")
                    Label("Исходная HTTPS-ссылка — не сохраняется", systemImage: "link.badge.plus")
                }
            }
            .navigationTitle("Добавить профиль")
            .navigationBarTitleDisplayMode(.inline)
            .interactiveDismissDisabled(isImporting)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Отмена") { dismiss() }
                        .disabled(isImporting)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button {
                        importProfiles()
                    } label: {
                        if isImporting { ProgressView() } else { Text("Импорт") }
                    }
                    .disabled(link.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || isImporting)
                }
            }
            .alert("Импорт остановлен", isPresented: errorBinding) {
                Button("Понятно", role: .cancel) { errorMessage = nil }
            } message: {
                Text(errorMessage ?? "Неизвестная ошибка")
            }
        }
    }

    private var errorBinding: Binding<Bool> {
        Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
    }

    private func importProfiles() {
        let input = link
        isImporting = true
        Task {
            defer { isImporting = false }
            do {
                let policy = try SecurityPolicy.load()
                let imported = try await SubscriptionImporter(policy: policy).importInput(input)
                try profiles.add(imported)
                link = ""
                dismiss()
            } catch {
                errorMessage = (error as? LocalizedError)?.errorDescription ?? "Не удалось импортировать профиль."
            }
        }
    }
}
