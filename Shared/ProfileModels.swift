import Foundation

enum ProfilePayloadKind: String, Codable, Sendable {
    case xrayJSON
    case shareLink
}

struct StoredProfilePayload: Codable, Sendable, Equatable {
    let version: Int
    let kind: ProfilePayloadKind
    let content: String
    let importedAt: Date

    init(kind: ProfilePayloadKind, content: String, importedAt: Date = Date()) {
        self.version = 1
        self.kind = kind
        self.content = content
        self.importedAt = importedAt
    }
}

struct ProfileSummary: Codable, Identifiable, Sendable, Equatable {
    let id: UUID
    var name: String
    let sourceHost: String?
    let importedAt: Date
}

struct ImportedProfile: Sendable, Equatable {
    let suggestedName: String
    let sourceHost: String?
    let payload: StoredProfilePayload
}

