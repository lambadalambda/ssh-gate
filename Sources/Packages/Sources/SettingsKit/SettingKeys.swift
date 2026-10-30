import Foundation

struct RequireDestinationInformationSettingsKey: SettingsStore.SettingsKey {
    static let defaultValue: Bool = true
}

struct GrantCertificateAuthoritySettingsKey: SettingsStore.SettingsKey {
    static let defaultValue: Data? = nil
}

extension SettingsStore {

    /// The public key blob of the secret that signs certificates for login grants, or `nil` for no certificates.
    public var grantCertificateAuthority: Data? {
        get { self[GrantCertificateAuthoritySettingsKey.self] }
        set { self[GrantCertificateAuthoritySettingsKey.self] = newValue }
    }

    public var requireDestinationInformation: Bool {
        get { self[RequireDestinationInformationSettingsKey.self] }
        set { self[RequireDestinationInformationSettingsKey.self] = newValue }
    }

}
