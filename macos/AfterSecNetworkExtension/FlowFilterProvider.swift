import NetworkExtension

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
              let remote = socket.remoteEndpoint as? NWHostEndpoint,
              let sink else { return .drop() }
        let parts = remote.port
        let port = UInt16(parts) ?? 0
        guard port > 0 else { return .drop() }
        sink.send(ProviderEvent(kind: "network_flow", pid: 0, process: "",
                                localAddress: nil, localPort: nil,
                                remoteAddress: remote.hostname, remotePort: port,
                                protocolName: nil, domain: nil,
                                timestamp: Int64(Date().timeIntervalSince1970)))
        return .allow()
    }
}
