import NetworkExtension
import Darwin

final class AfterSecFlowFilterProvider: NEFilterDataProvider {
    private var sink: EventSink?
    private struct FlowState {
        let pid: Int32
        let process: String
        let uid: UInt32
        let local: NWHostEndpoint
        let remote: NWHostEndpoint
        let started: Int64
        var lastSeen: Int64
        var sent: UInt64
        var received: UInt64
    }
    private var udpFlows: [UUID: FlowState] = [:]
    private let stateQueue = DispatchQueue(label: "com.aftersec.flow-state")
    private let maxUDPFlows = 65_536
    private let udpIdleSeconds: Int64 = 300

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
        stateQueue.sync {
            udpFlows.removeAll(keepingCapacity: false)
        }
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
                                  startedTimestamp: nil,
                                  timestamp: Int64(Date().timeIntervalSince1970))
        guard sink.send(event) else { return .drop() }
        if proto == "udp" {
            let accepted = stateQueue.sync {
                let now = Int64(Date().timeIntervalSince1970)
                udpFlows = udpFlows.filter { now - $0.value.lastSeen <= udpIdleSeconds }
                guard udpFlows.count < maxUDPFlows else { return false }
                udpFlows[flow.identifier] = FlowState(
                    pid: identity.pid, process: process, uid: identity.uid,
                    local: local, remote: remote,
                    started: now, lastSeen: now, sent: 0, received: 0)
                return true
            }
            guard accepted else { return .drop() }
            return NEFilterNewFlowVerdict.filterDataVerdict(
                withFilterInbound: true, peekInboundBytes: 1,
                filterOutbound: true, peekOutboundBytes: 1)
        }
        return .allow()
    }

    override func handleInboundData(from flow: NEFilterFlow, readBytesStartOffset: Int,
                                    readBytes: Data) -> NEFilterDataVerdict {
        return account(flow: flow, sent: 0, received: UInt64(readBytes.count))
            ? NEFilterDataVerdict(passBytes: readBytes.count, peekBytes: 1) : .drop()
    }

    override func handleOutboundData(from flow: NEFilterFlow, readBytesStartOffset: Int,
                                     readBytes: Data) -> NEFilterDataVerdict {
        return account(flow: flow, sent: UInt64(readBytes.count), received: 0)
            ? NEFilterDataVerdict(passBytes: readBytes.count, peekBytes: 1) : .drop()
    }

    private func account(flow: NEFilterFlow, sent: UInt64, received: UInt64) -> Bool {
        guard let sink else { return false }
        return stateQueue.sync {
            guard var state = udpFlows[flow.identifier],
                  let localPort = UInt16(state.local.port),
                  let remotePort = UInt16(state.remote.port) else { return false }
            state.lastSeen = Int64(Date().timeIntervalSince1970)
            state.sent += sent
            state.received += received
            udpFlows[flow.identifier] = state
            let event = ProviderEvent(
                kind: "network_flow", pid: state.pid, process: state.process, uid: state.uid,
                localAddress: state.local.hostname, localPort: localPort,
                remoteAddress: state.remote.hostname, remotePort: remotePort,
                protocolName: "udp", bytesSent: state.sent, bytesReceived: state.received,
                domain: nil, startedTimestamp: state.started,
                timestamp: Int64(Date().timeIntervalSince1970))
            return sink.send(event)
        }
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
