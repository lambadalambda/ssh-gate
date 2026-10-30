import Foundation
import Security

/// The code signing requirement between the app and its XPC services: both must be signed by the same team.
enum XPCCodeSigning {

    #if DEBUG
    static let isDebug = true
    #else
    static let isDebug = false
    #endif

    /// The requirement for the peer of an XPC connection.
    /// - Returns: A requirement for `teamID`; `nil` (no requirement) for unsigned debug builds; `"never"` for
    ///   unsigned release builds and malformed team IDs, so they fail closed.
    static func requirement(teamID: String?, debug: Bool = isDebug) -> String? {
        guard let teamID else {
            return debug ? nil : "never"
        }
        guard teamID.count == 10, teamID.allSatisfy({ ("A"..."Z").contains($0) || ("0"..."9").contains($0) }) else {
            return "never"
        }
        return "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\""
    }

    /// The team ID of the running process's code signature, if it has one.
    static let ownTeamID: String? = {
        var code: SecCode?
        guard unsafe SecCodeCopySelf([], &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard unsafe SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        var information: CFDictionary?
        guard unsafe SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let information = information as? [String: Any] else {
            return nil
        }
        return information[kSecCodeInfoTeamIdentifier as String] as? String
    }()

    static func apply(to connection: NSXPCConnection) {
        if let requirement = requirement(teamID: ownTeamID) {
            connection.setCodeSigningRequirement(requirement)
        }
    }

}
