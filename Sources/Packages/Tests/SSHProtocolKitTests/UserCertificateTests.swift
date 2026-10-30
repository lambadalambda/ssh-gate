import Foundation
import CryptoKit
import Testing
@testable import SSHProtocolKit
import SSHTestFixtures

@Suite struct UserCertificateTests {

    /// A P-256 CA in OpenSSH wire format, signing like ssh-keygen does.
    struct TestCA {
        let key = P256.Signing.PrivateKey()
        var blob: Data {
            var data = Data("ecdsa-sha2-nistp256".utf8).lengthAndData
            data.append(Data("nistp256".utf8).lengthAndData)
            data.append(key.publicKey.x963Representation.lengthAndData)
            return data
        }
        func sign(_ data: Data) throws -> Data {
            let raw = try key.signature(for: data).rawRepresentation
            func mpint(_ bytes: Data) -> Data {
                var trimmed = Data(bytes.drop { $0 == 0 })
                if let first = trimmed.first, first & 0x80 != 0 { trimmed.insert(0, at: 0) }
                return trimmed.lengthAndData
            }
            var signature = Data("ecdsa-sha2-nistp256".utf8).lengthAndData
            signature.append((mpint(raw.prefix(32)) + mpint(raw.suffix(32))).lengthAndData)
            return signature
        }
    }

    func certificate(ca: TestCA, principals: [String] = ["git"]) throws -> (Data, UserCertificate.Request) {
        let request = UserCertificate.Request(
            publicKey: CapturedFixtures.userKey,
            serial: 42,
            keyID: "secretive grant: /bin/claude pid 7",
            principals: principals,
            validAfter: 1_000,
            validBefore: 2_000,
            authority: ca.blob
        )
        let toBeSigned = try request.toBeSigned(nonce: Data(repeating: 9, count: 32))
        return (UserCertificate.assemble(toBeSigned: toBeSigned, signature: try ca.sign(toBeSigned)), request)
    }

    @Test func fieldsAndCASignature() throws {
        let ca = TestCA()
        let (blob, _) = try certificate(ca: ca)
        let fields = try HostCertificate.Fields(blob)
        #expect(fields.certType == "ssh-ed25519-cert-v01@openssh.com")
        #expect(fields.type == 1)
        #expect(fields.serial == 42)
        #expect(String(decoding: fields.keyID, as: UTF8.self) == "secretive grant: /bin/claude pid 7")
        #expect(fields.principals == Data("git".utf8).lengthAndData)
        #expect(fields.validAfter == 1_000 && fields.validBefore == 2_000)
        #expect(fields.criticalOptions.isEmpty)
        #expect(fields.signatureKey == ca.blob)
        let signed = blob.prefix(blob.count - 4 - fields.signature.count)
        try HostKeySignatureVerifier.verify(hostKey: ca.blob, signature: fields.signature, data: Data(signed))
    }

    @Test func extensionsWithoutAgentForwarding() throws {
        let (blob, _) = try certificate(ca: TestCA())
        let reader = OpenSSHReader(data: try HostCertificate.Fields(blob).extensions)
        var names: [String] = []
        while !reader.done {
            names.append(try reader.readNextChunkAsString())
            #expect(try reader.readNextChunk().isEmpty)
        }
        #expect(names == ["permit-port-forwarding", "permit-pty", "permit-user-rc"])
    }

    @Test func sshKeygenAcceptsCertificate() throws {
        let (blob, _) = try certificate(ca: TestCA(), principals: ["git", "deploy"])
        let file = FileManager.default.temporaryDirectory.appending(path: "cert-\(UUID().uuidString)-cert.pub")
        try Data("ssh-ed25519-cert-v01@openssh.com \(blob.base64EncodedString())\n".utf8).write(to: file)
        defer { try? FileManager.default.removeItem(at: file) }
        let process = Process()
        process.executableURL = URL(filePath: "/usr/bin/ssh-keygen")
        process.arguments = ["-L", "-f", file.path()]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        process.waitUntilExit()
        let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        #expect(process.terminationStatus == 0, "\(output)")
        #expect(output.contains("Type: ssh-ed25519-cert-v01@openssh.com user certificate"))
        #expect(output.contains("Serial: 42"))
        #expect(output.contains("deploy"))
    }

    @Test func unsupportedKeyType() {
        let request = UserCertificate.Request(publicKey: Data("ssh-dss".utf8).lengthAndData, serial: 1, keyID: "", principals: ["a"], validAfter: 0, validBefore: 1, authority: Data())
        #expect(throws: (any Error).self) { try request.toBeSigned(nonce: Data(count: 32)) }
    }

}
