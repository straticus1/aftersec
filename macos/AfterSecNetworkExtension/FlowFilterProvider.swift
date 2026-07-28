import NetworkExtension
import Darwin

final class AfterSecFlowFilterProvider: NEFilterDataProvider {
    private var sink: EventSink?

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        // The extension must be provisioned with NetworkExtension entitlement;
        // without the authenticated event sink we refuse to start.
        sink = EventSink(path: "/var/run/aftersec/network-events.jsonl")
        guard sink != nil else {
            completionHandler(NSError(domain: "AfterSecNetworkExtension", code: 1,
                                       userInfo: [NSLocalizedDescriptionKey: "event sink unavailable"]))
            return
        }
        completionHandler(nil)
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        sink = nil
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socket = flow as? NEFilterSocketFlow,
              let local = socket.localEndpoint as? NWHostEndpoint,
              let remote = socket.remoteEndpoint as? NWHostEndpoint,
              let sink,
              let audit = flow.sourceAppAuditToken,
              let identity = auditIdentity(audit),
              let localPort = UInt16(local.port),
              let remotePort = UInt16(remote.port),
              localPort > 0, remotePort > 0,
              let process = processPath(identity.pid) else { return .drop() }
        let proto = socket.socketProtocol == IPPROTO_UDP ? "udp" : "tcp"
        let event = ProviderEvent(kind: "network_flow", pid: identity.pid, process: process,
                                  uid: identity.uid,
                                  localAddress: local.hostname, localPort: localPort,
                                  remoteAddress: remote.hostname, remotePort: remotePort,
                                  protocolName: proto, bytesSent: 0, bytesReceived: 0,
                                  domain: nil,
                                  timestamp: Int64(Date().timeIntervalSince1970))
        return sink.send(event) ? .allow() : .drop()
    }

    private func auditIdentity(_ data: Data) -> (pid: Int32, uid: UInt32)? {
        guard data.count == MemoryLayout<UInt32>.size * 8 else { return nil }
        var words = [UInt32](repeating: 0, count: 8)
        _ = words.withUnsafeMutableBytes { data.copyBytes(to: $0) }
        let pid = Int32(bitPattern: words[5])
        guard pid > 0 else { return nil }
        return (pid, words[1])
    }

    private func processPath(_ pid: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: 4_096)
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return nil }
        let path = String(cString: buffer)
        return path.isEmpty ? nil : path
    }
}
