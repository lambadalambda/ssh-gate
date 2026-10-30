import Foundation

/// Names of the XPC services that are bundled with the app.
public enum XPCServiceName {

    static let upstreamBase = "com.maxgoedjen.Secretive"

    /// The service's bundle ID: the main bundle ID without its last component (e.g. "Host" or "SecretAgent"), plus
    /// `name`. Builds with their own bundle ID therefore find their own services.
    public static func named(_ name: String, mainBundleID: String? = Bundle.main.bundleIdentifier) -> String {
        guard let mainBundleID, let dot = mainBundleID.lastIndex(of: ".") else {
            return "\(upstreamBase).\(name)"
        }
        return "\(mainBundleID[..<dot]).\(name)"
    }

}
