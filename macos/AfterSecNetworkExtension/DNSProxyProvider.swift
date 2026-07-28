import NetworkExtension
import Network
import Darwin

final class AfterSecDNSProxyProvider: NEDNSProxyProvider {
    private var sink: EventSink?
    private let queue = DispatchQueue(label: "com.aftersec.dns-proxy")
    private var tcpBuffers: [ObjectIdentifier: Data] = [:]
    private var tcpConnections: [ObjectIdentifier: NWConnection] = [:]

    override func startProxy(options: [String : Any]?, completionHandler: @escaping (Error?) -> Void) {
        sink = EventSink(path: "/var/run/aftersec/dns-events.jsonl")
        guard sink != nil else {
            completionHandler(NSError(domain: "AfterSecDNSProxy", code: 1,
                                       userInfo: [NSLocalizedDescriptionKey: "event sink unavailable"]))
            return
        }
        completionHandler(nil)
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        sink = nil
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let sink,
              let audit = flow.metaData.sourceAppAuditToken,
              let identity = auditIdentity(audit),
              let process = processPath(identity.pid) else { return false }
        if let tcp = flow as? NEAppProxyTCPFlow {
            return startTCP(tcp, sink: sink, identity: identity, process: process)
        }
        guard let udp = flow as? NEAppProxyUDPFlow else { return false }
        udp.open(withLocalEndpoint: nil) { [weak self, weak udp] error in
            guard error == nil, let self, let udp else {
                udp?.closeReadWithError(error)
                udp?.closeWriteWithError(error)
                return
            }
            self.read(udp, sink: sink, identity: identity, process: process)
        }
        return true
    }

    private func startTCP(_ flow: NEAppProxyTCPFlow, sink: EventSink,
                          identity: (pid: Int32, uid: UInt32), process: String) -> Bool {
        guard let endpoint = flow.remoteEndpoint as? NWHostEndpoint,
              let portValue = UInt16(endpoint.port),
              let port = Network.NWEndpoint.Port(rawValue: portValue) else { return false }
        let remote = Network.NWEndpoint.hostPort(
            host: Network.NWEndpoint.Host(endpoint.hostname), port: port)
        let connection = NWConnection(to: remote, using: .tcp)
        let key = ObjectIdentifier(flow)
        tcpBuffers[key] = Data()
        tcpConnections[key] = connection
        connection.stateUpdateHandler = { [weak self, weak flow] state in
            guard let self, let flow else { return }
            if case .ready = state {
                flow.open(withLocalEndpoint: nil) { error in
                    guard error == nil else {
                        self.finishTCP(key, flow: flow, error: error)
                        return
                    }
                    self.readTCP(flow, key: key, sink: sink, identity: identity, process: process)
                    self.receiveTCP(connection, flow: flow, key: key)
                }
            } else if case .failed(let error) = state {
                self.finishTCP(key, flow: flow, error: error)
            }
        }
        connection.start(queue: queue)
        return true
    }

    private func readTCP(_ flow: NEAppProxyTCPFlow, key: ObjectIdentifier, sink: EventSink,
                         identity: (pid: Int32, uid: UInt32), process: String) {
        flow.readData { [weak self, weak flow] data, error in
            guard let self, let flow, let data, !data.isEmpty, error == nil,
                  let connection = self.tcpConnections[key] else {
                self?.finishTCP(key, flow: flow, error: error)
                return
            }
            var buffer = self.tcpBuffers[key] ?? Data()
            buffer.append(data)
            while buffer.count >= 2 {
                let length = Int(buffer[0]) << 8 | Int(buffer[1])
                guard length > 0 && length <= 65_535 else {
                    self.finishTCP(key, flow: flow, error: Self.proxyError("invalid TCP DNS frame"))
                    return
                }
                if buffer.count < length + 2 { break }
                let packet = Data(buffer[2..<(length + 2)])
                guard let domain = self.questionName(packet) else {
                    self.finishTCP(key, flow: flow, error: Self.proxyError("invalid TCP DNS question"))
                    return
                }
                let event = ProviderEvent(kind: "dns_query", pid: identity.pid, process: process,
                                          uid: identity.uid, localAddress: nil, localPort: nil,
                                          remoteAddress: nil, remotePort: 53, protocolName: "tcp",
                                          bytesSent: UInt64(packet.count), bytesReceived: nil,
                                          domain: domain,
                                          startedTimestamp: nil,
                                          timestamp: Int64(Date().timeIntervalSince1970))
                guard sink.send(event) else {
                    self.finishTCP(key, flow: flow, error: Self.proxyError("event sink write failed"))
                    return
                }
                buffer.removeFirst(length + 2)
            }
            self.tcpBuffers[key] = buffer
            connection.send(content: data, completion: .contentProcessed { sendError in
                guard sendError == nil else {
                    self.finishTCP(key, flow: flow, error: sendError)
                    return
                }
                self.readTCP(flow, key: key, sink: sink, identity: identity, process: process)
            })
        }
    }

    private func receiveTCP(_ connection: NWConnection, flow: NEAppProxyTCPFlow,
                            key: ObjectIdentifier) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_537) {
            [weak self, weak flow] data, _, complete, error in
            guard let self, let flow else { return }
            if let data, !data.isEmpty {
                flow.write(data) { writeError in
                    if writeError != nil {
                        self.finishTCP(key, flow: flow, error: writeError)
                    }
                }
            }
            if complete || error != nil {
                self.finishTCP(key, flow: flow, error: error)
            } else {
                self.receiveTCP(connection, flow: flow, key: key)
            }
        }
    }

    private func finishTCP(_ key: ObjectIdentifier, flow: NEAppProxyTCPFlow?, error: Error?) {
        tcpConnections.removeValue(forKey: key)?.cancel()
        tcpBuffers.removeValue(forKey: key)
        flow?.closeReadWithError(error)
        flow?.closeWriteWithError(error)
    }

    private func read(_ flow: NEAppProxyUDPFlow, sink: EventSink,
                      identity: (pid: Int32, uid: UInt32), process: String) {
        flow.readDatagrams { [weak self, weak flow] datagrams, endpoints, error in
            guard let self, let flow, error == nil,
                  let datagrams, let endpoints, datagrams.count == endpoints.count else {
                flow?.closeReadWithError(error)
                flow?.closeWriteWithError(error)
                return
            }
            for (packet, endpoint) in zip(datagrams, endpoints) {
                guard let domain = self.questionName(packet) else {
                    flow.closeReadWithError(Self.proxyError("invalid DNS question"))
                    flow.closeWriteWithError(Self.proxyError("invalid DNS question"))
                    return
                }
                let event = ProviderEvent(kind: "dns_query", pid: identity.pid, process: process,
                                          uid: identity.uid,
                                          localAddress: nil, localPort: nil,
                                          remoteAddress: nil, remotePort: 53,
                                          protocolName: "udp",
                                          bytesSent: UInt64(packet.count), bytesReceived: nil,
                                          domain: domain,
                                          startedTimestamp: nil,
                                          timestamp: Int64(Date().timeIntervalSince1970))
                guard sink.send(event) else {
                    flow.closeReadWithError(Self.proxyError("event sink write failed"))
                    flow.closeWriteWithError(Self.proxyError("event sink write failed"))
                    return
                }
                guard let hostEndpoint = endpoint as? NWHostEndpoint else {
                    flow.closeReadWithError(Self.proxyError("unsupported DNS endpoint"))
                    flow.closeWriteWithError(Self.proxyError("unsupported DNS endpoint"))
                    return
                }
                self.forward(packet, endpoint: hostEndpoint, to: flow)
            }
            self.read(flow, sink: sink, identity: identity, process: process)
        }
    }

    private func forward(_ packet: Data, endpoint: NWHostEndpoint, to flow: NEAppProxyUDPFlow) {
        guard let portValue = UInt16(endpoint.port),
              let port = Network.NWEndpoint.Port(rawValue: portValue) else { return }
        let remote = Network.NWEndpoint.hostPort(
            host: Network.NWEndpoint.Host(endpoint.hostname), port: port)
        let connection = NWConnection(to: remote, using: .udp)
        connection.stateUpdateHandler = { (state: NWConnection.State) in
            if case .ready = state {
                connection.send(content: packet,
                                completion: NWConnection.SendCompletion.contentProcessed { sendError in
                    guard sendError == nil else {
                        connection.cancel()
                        return
                    }
                    connection.receiveMessage { response, _, _, _ in
                        defer { connection.cancel() }
                        guard let response else { return }
                        flow.writeDatagrams([response], sentBy: [endpoint]) { _ in }
                    }
                })
            }
        }
        connection.start(queue: queue)
    }

    private func questionName(_ packet: Data) -> String? {
        guard packet.count >= 13, packet[2] & 0x80 == 0,
              packet[4] != 0 || packet[5] != 0 else { return nil }
        var offset = 12
        var labels: [String] = []
        var terminated = false
        while offset < packet.count {
            let length = Int(packet[offset])
            offset += 1
            if length == 0 {
                terminated = true
                break
            }
            guard length <= 63, offset + length <= packet.count,
                  let label = String(data: packet[offset..<(offset + length)], encoding: .ascii),
                  !label.isEmpty else { return nil }
            labels.append(label)
            offset += length
            guard labels.count <= 127 else { return nil }
        }
        let domain = labels.joined(separator: ".")
        return !terminated || domain.isEmpty || domain.utf8.count > 253 ? nil : domain
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

    private static func proxyError(_ message: String) -> Error {
        NSError(domain: "AfterSecDNSProxy", code: 2,
                userInfo: [NSLocalizedDescriptionKey: message])
    }
}
