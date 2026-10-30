import SwiftUI
import SecretKit
import Common
import CertificateKit
import SSHProtocolKit
import SettingsKit

struct SecretDetailView<SecretType: Secret>: View {
    
    let secret: SecretType
    let certificates: [Certificate]
    let navigateToCertificate: ((Certificate) -> Void)?

    private let keyWriter = OpenSSHPublicKeyWriter()
    @Environment(\.settingsStore) private var settingsStore

    var body: some View {
        ScrollView {
            Form {
                Section {
                    CopyableView(
                        title: .secretDetailSha256FingerprintLabel,
                        image: Image(systemName: "touchid"),
                        text: keyWriter.openSSHSHA256Fingerprint(secret: secret)
                    )
                    Spacer()
                        .frame(height: 20)
                    CopyableView(
                        title: .secretDetailMd5FingerprintLabel,
                        image: Image(systemName: "touchid"),
                        text: keyWriter.openSSHMD5Fingerprint(secret: secret)
                    )
                    Spacer()
                        .frame(height: 20)
                    CopyableView(
                        title: .secretDetailPublicKeyLabel,
                        image: Image(systemName: "key"),
                        text: keyWriter.openSSHString(secret: secret)
                    )
                    Spacer()
                        .frame(height: 20)
                    CopyableView(
                        title: .secretDetailPublicKeyPathLabel,
                        image: Image(systemName: "lock.doc"),
                        text: URL.publicKeyPath(for: secret, in: URL.publicKeyDirectory),
                        showRevealInFinder: true
                    )
                    if !certificates.isEmpty {
                        Spacer()
                            .frame(height: 20)
                        MultilineInfoView(title: .secretDetailCertificatePathLabel, image: Image(systemName: "checkmark.seal.text.page")) {
                            ForEach(certificates) { certificate in
                                Text(certificate.name)
                                    .multilineItemAction(image: Image(systemName: "chevron.forward")) {
                                        navigateToCertificate?(certificate)
                                    }
                            }
                        }
                    }
                    Spacer()
                        .frame(height: 20)
                    GrantAuthoritySection(secret: secret, keyWriter: keyWriter, settingsStore: settingsStore)
                    Spacer()
                }
            }
            .padding()
        }
        .frame(minHeight: 200, maxHeight: .infinity)
    }


}

//#Preview {
//    SecretDetailView(secret: Preview.Secret(name: "Demonstration Secret"))
//}

/// Marks the secret as the CA for grant certificates and shows how servers trust it.
private struct GrantAuthoritySection<SecretType: Secret>: View {

    let secret: SecretType
    let keyWriter: OpenSSHPublicKeyWriter
    @Bindable var settingsStore: SettingsStore

    private var blob: Data { keyWriter.data(secret: secret) }

    private var isAuthority: Binding<Bool> {
        Binding(
            get: { settingsStore.grantCertificateAuthority == blob },
            set: { settingsStore.grantCertificateAuthority = $0 ? blob : nil }
        )
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Toggle("Sign grant certificates with this key", isOn: isAuthority)
            Text("When you approve a login grant, the agent signs a certificate for the granted key that is valid only for the approved user and until the grant expires. Servers that trust this key as a user CA enforce the expiry themselves. Clients cannot use this key directly. If it requires authentication, you confirm each certificate a second time.")
                .font(.caption)
                .foregroundStyle(.secondary)
            if isAuthority.wrappedValue {
                CopyableView(
                    title: "Line for ~/.ssh/authorized_keys (replace the principal)",
                    image: Image(systemName: "server.rack"),
                    text: "cert-authority,principals=\"USER\" " + keyWriter.openSSHString(secret: secret)
                )
                Text("Or system-wide: save the public key in a file and set TrustedUserCAKeys to it in sshd_config.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

}
