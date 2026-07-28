import Foundation

struct ProviderEvent: Codable {
    let kind: String
    let pid: Int32
    let process: String
    let uid: UInt32?
    let localAddress: String?
    let localPort: UInt16?
    let remoteAddress: String?
    let remotePort: UInt16?
    let protocolName: String?
    let bytesSent: UInt64?
    let bytesReceived: UInt64?
    let domain: String?
    let startedTimestamp: Int64?
    let timestamp: Int64
}

final class EventSink {
    private let handle: FileHandle
    private let encoder = JSONEncoder()
    private let queue = DispatchQueue(label: "com.aftersec.provider-events")

    init?(path: String) {
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        guard let h = FileHandle(forWritingAtPath: path) else { return nil }
        do {
            try h.seekToEnd()
        } catch {
            try? h.close()
            return nil
        }
        handle = h
    }

    func send(_ event: ProviderEvent) -> Bool {
        queue.sync { [handle, encoder] in
            guard let data = try? encoder.encode(event), data.count <= 16 * 1024 else { return false }
            do {
                try handle.write(contentsOf: data + Data([0x0a]))
                try handle.synchronize()
                return true
            } catch {
                return false
            }
        }
    }
}
