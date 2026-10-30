import Foundation

extension Data {

    /// Creates an OpenSSH protocol style data object, which has a length header, followed by the data payload.
    /// - Returns: OpenSSH data.
    package var lengthAndData: Data {
        let rawLength = UInt32(count)
        var endian = rawLength.bigEndian
        return unsafe Data(bytes: &endian, count: MemoryLayout<UInt32>.size) + self
    }

}

extension String {

    /// Creates an OpenSSH protocol style data object, which has a length header, followed by the data payload.
    /// - Returns: OpenSSH data.
    package var lengthAndData: Data {
        Data(utf8).lengthAndData
    }

}

extension Data {

    /// An integer in network byte order, as in SSH's uint32 and uint64.
    static func bigEndian<T: FixedWidthInteger>(_ value: T) -> Data {
        Data((0..<T.bitWidth / 8).reversed().map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) })
    }

}
