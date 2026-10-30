import Foundation
import Testing
@testable import SSHProtocolKit
import SSHTestFixtures

@Suite struct HostCertificateTests {

    static let names = CapturedFixtures.certLogins.keys.sorted()

    @Test(arguments: names)
    func parsesCertificate(name: String) throws {
        let login = try #require(CapturedFixtures.certLogins[name])
        let certificate = try HostCertificate(login.certificate)
        #expect(certificate.publicKey == login.hostKey)
        #expect(certificate.principals == ["127.0.0.1", "test.example"])
        #expect(try OpenSSHReader(data: certificate.authority).readNextChunkAsString() == "ssh-ed25519")
    }

    @Test(arguments: names)
    func bindUsesInnerKey(name: String) throws {
        let login = try #require(CapturedFixtures.certLogins[name])
        let bind = try parseBind(login.sessionBind)
        #expect(bind.hostKey == login.hostKey)
        #expect(bind.certificate?.principals == ["127.0.0.1", "test.example"])
        let payload = try parseConnection(login.signRequest)
        #expect(payload.hostKey == login.hostKey)
        #expect(payload.sessionID == bind.sessionID)
    }

    @Test func plainBindHasNoCertificate() throws {
        #expect(try parseBind(try #require(CapturedFixtures.logins["ed25519"]).sessionBind).certificate == nil)
    }

    @Test func forgedCASignatureIsRejected() throws {
        var certificate = try #require(CapturedFixtures.certLogins["ed25519c"]).certificate
        certificate[certificate.count - 5] ^= 0x01 // inside the CA signature
        #expect(throws: (any Error).self) { try HostCertificate(certificate) }
    }

    @Test func changedPrincipalsAreRejected() throws {
        let original = try #require(CapturedFixtures.certLogins["ed25519c"]).certificate
        let tampered = try #require(Self.replacing(Data("test.example".utf8), with: Data("evil.example".utf8), in: original))
        #expect(throws: (any Error).self) { try HostCertificate(tampered) }
    }

    @Test func userCertificateIsNotAHostCertificate() throws {
        // Certificate type is the uint32 after the serial; flip it from 2 (host) to 1 (user).
        let original = try #require(CapturedFixtures.certLogins["ed25519c"]).certificate
        var parts = try HostCertificate.Fields(original)
        parts.type = 1
        #expect(throws: (any Error).self) { try HostCertificate(parts.encoded()) }
    }

    @Test func validityPeriod() throws {
        let certificate = try HostCertificate(try #require(CapturedFixtures.certLogins["ed25519c"]).certificate)
        #expect(certificate.isValid(at: Date()))
        #expect(!certificate.isValid(at: Date(timeIntervalSince1970: 0)))
        #expect(!certificate.isValid(at: Date().addingTimeInterval(20 * 365 * 24 * 3600)))
    }

    @Test func trailingDataIsRejected() throws {
        let original = try #require(CapturedFixtures.certLogins["ed25519c"]).certificate
        #expect(throws: (any Error).self) { try HostCertificate(original + Data([0])) }
    }

    @Test func certificateAsCAIsRejected() throws {
        let original = try #require(CapturedFixtures.certLogins["ed25519c"]).certificate
        var fields = try HostCertificate.Fields(original)
        fields.signatureKey = original
        #expect(throws: (any Error).self) { try HostCertificate(fields.encoded()) }
    }

    static func replacing(_ old: Data, with new: Data, in data: Data) -> Data? {
        guard let range = data.range(of: old) else { return nil }
        var copy = data
        copy.replaceSubrange(range, with: new)
        return copy
    }

}

extension HostCertificate.Fields {

    /// Encodes the fields again, so tests can change single fields.
    func encoded() -> Data {
        func bigEndian<T: FixedWidthInteger>(_ value: T) -> Data {
            Data((0..<T.bitWidth / 8).reversed().map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) })
        }
        var data = Data(certType.utf8).lengthAndData
        data.append(nonce.lengthAndData)
        for field in keyFields {
            data.append(field.lengthAndData)
        }
        data.append(bigEndian(serial))
        data.append(bigEndian(type))
        data.append(keyID.lengthAndData)
        data.append(principals.lengthAndData)
        data.append(bigEndian(validAfter))
        data.append(bigEndian(validBefore))
        for chunk in [criticalOptions, extensions, reserved, signatureKey, signature] {
            data.append(chunk.lengthAndData)
        }
        return data
    }

}
