import Foundation

@MainActor
final class ProfileRepository: ObservableObject {
    @Published private(set) var profiles: [ProfileSummary]
    @Published var selectedProfileID: UUID?

    private let selectedKey = "selected-profile-id-v1"
    private let defaults = ProfileMetadataStore.defaults

    init() {
        let loaded = ProfileMetadataStore.load()
        self.profiles = loaded
        if let raw = defaults.string(forKey: selectedKey), let id = UUID(uuidString: raw),
           loaded.contains(where: { $0.id == id }) {
            self.selectedProfileID = id
        } else {
            self.selectedProfileID = loaded.first?.id
        }
    }

    var selectedProfile: ProfileSummary? {
        guard let selectedProfileID else { return nil }
        return profiles.first { $0.id == selectedProfileID }
    }

    func select(_ id: UUID) {
        guard profiles.contains(where: { $0.id == id }) else { return }
        selectedProfileID = id
        defaults.set(id.uuidString, forKey: selectedKey)
    }

    func add(_ imported: [ImportedProfile]) throws {
        var updated = profiles
        var savedIDs: [UUID] = []
        var firstNewID: UUID?
        do {
            for profile in imported {
                let id = UUID()
                firstNewID = firstNewID ?? id
                try SecureProfileStore.save(payload: profile.payload, id: id)
                savedIDs.append(id)
                updated.append(ProfileSummary(
                    id: id,
                    name: profile.suggestedName,
                    sourceHost: profile.sourceHost,
                    importedAt: profile.payload.importedAt
                ))
            }
            try ProfileMetadataStore.save(updated)
            profiles = updated
            if selectedProfileID == nil, let firstNewID {
                select(firstNewID)
            }
        } catch {
            for id in savedIDs { try? SecureProfileStore.delete(id: id) }
            throw error
        }
    }

    func delete(_ profile: ProfileSummary) throws {
        try SecureProfileStore.delete(id: profile.id)
        let updated = profiles.filter { $0.id != profile.id }
        try ProfileMetadataStore.save(updated)
        profiles = updated
        if selectedProfileID == profile.id {
            selectedProfileID = updated.first?.id
            defaults.set(selectedProfileID?.uuidString, forKey: selectedKey)
        }
    }
}
