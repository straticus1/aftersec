import NetworkExtension

final class AfterSecDNSProxyProvider: NEDNSProxyProvider {
    private var sink: EventSink?

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
}
