import Foundation

struct ProviderEvent: Codable {
    let kind: String
    let pid: Int32
    let process: String
    let localAddress: String?
    let localPort: UInt16?
    let remoteAddress: String?
    let remotePort: UInt16?
    let protocolName: String?
    let domain: String?
    let timestamp: Int64
}

final class EventSink {
    private let handle: FileHandle
    private let encoder = JSONEncoder()
    private let queue = DispatchQueue(label: "com.aftersec.provider-events")

    init?(path: String) {
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        guard let h = FileHandle(forWritingAtPath: path) else { return nil }
        handle = h
    }

    func send(_ event: ProviderEvent) {
        queue.async { [handle, encoder] in
            guard let data = try? encoder.encode(event), data.count <= 16 * 1024 else { return }
            try? handle.write(contentsOf: data + Data([0x0a]))
        }
    }
}
