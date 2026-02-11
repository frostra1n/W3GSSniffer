import CLibpcap
import Foundation

/// Configuration for a live packet capture session.
public struct CaptureConfiguration: Sendable {
    /// Network interface name (e.g. "en0", "bridge100").
    public var interface: String
    /// Maximum bytes to capture per packet.
    public var snapLength: Int32
    /// Whether to enable promiscuous mode.
    public var promiscuous: Bool
    /// Read timeout in milliseconds.
    public var timeoutMs: Int32
    /// BPF filter expression (e.g. "tcp").
    public var filter: String?

    public init(
        interface: String,
        snapLength: Int32 = 65535,
        promiscuous: Bool = true,
        timeoutMs: Int32 = 100,
        filter: String? = nil
    ) {
        self.interface = interface
        self.snapLength = snapLength
        self.promiscuous = promiscuous
        self.timeoutMs = timeoutMs
        self.filter = filter
    }
}

/// Errors that can occur during packet capture.
public enum CaptureError: Error, Sendable, CustomStringConvertible {
    case interfaceNotFound(String)
    case activationFailed(String)
    case filterCompilationFailed(String)
    case permissionDenied(String)
    case captureError(String)

    public var description: String {
        switch self {
        case .interfaceNotFound(let msg):
            return "Interface not found: \(msg)"
        case .activationFailed(let msg):
            return "Activation failed: \(msg)"
        case .filterCompilationFailed(let msg):
            return "Filter compilation failed: \(msg)"
        case .permissionDenied(let msg):
            return "Permission denied: \(msg). Run with sudo or add your user to the access_bpf group."
        case .captureError(let msg):
            return "Capture error: \(msg)"
        }
    }
}

/// Captured packet data with timestamp.
struct CapturedPacket: Sendable {
    let data: Data
    let timestamp: PacketTimestamp
}

/// Internal wrapper around libpcap for live packet capture.
/// - Note: Thread safety is managed by usage patterns — `breakLoop()` is safe to call
///   from any thread per libpcap documentation.
final class PacketSource: @unchecked Sendable {
    private let handle: OpaquePointer

    private init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit {
        pcap_close(handle)
    }

    /// Open a live capture on the given interface.
    static func live(configuration: CaptureConfiguration) throws -> PacketSource {
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))

        guard let handle = pcap_open_live(
            configuration.interface,
            configuration.snapLength,
            configuration.promiscuous ? 1 : 0,
            configuration.timeoutMs,
            &errbuf
        ) else {
            let msg = String(decoding: errbuf.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }, as: UTF8.self)
            if msg.contains("permission") || msg.contains("Operation not permitted") {
                throw CaptureError.permissionDenied(msg)
            }
            if msg.contains("No such device") {
                throw CaptureError.interfaceNotFound(msg)
            }
            throw CaptureError.activationFailed(msg)
        }

        if let filter = configuration.filter {
            var bpf = bpf_program()
            guard pcap_compile(handle, &bpf, filter, 1, UInt32(PCAP_NETMASK_UNKNOWN)) == 0 else {
                let msg = String(cString: pcap_geterr(handle))
                pcap_close(handle)
                throw CaptureError.filterCompilationFailed(msg)
            }
            guard pcap_setfilter(handle, &bpf) == 0 else {
                let msg = String(cString: pcap_geterr(handle))
                pcap_freecode(&bpf)
                pcap_close(handle)
                throw CaptureError.filterCompilationFailed(msg)
            }
            pcap_freecode(&bpf)
        }

        return PacketSource(handle: handle)
    }

    /// Read the next packet. Returns `nil` on timeout (no packet available).
    /// Throws on error. Check `Task.isCancelled` between calls for cooperative cancellation.
    func nextPacket() throws -> CapturedPacket? {
        var header: UnsafeMutablePointer<pcap_pkthdr>?
        var data: UnsafePointer<UInt8>?

        let result = pcap_next_ex(handle, &header, &data)
        switch result {
        case 1:
            // Packet captured
            guard let hdr = header?.pointee, let pktData = data else { return nil }
            let packetData = Data(bytes: pktData, count: Int(hdr.caplen))
            let ts = PacketTimestamp(
                seconds: UInt32(hdr.ts.tv_sec),
                microseconds: UInt32(hdr.ts.tv_usec)
            )
            return CapturedPacket(data: packetData, timestamp: ts)
        case 0:
            // Timeout
            return nil
        case -2:
            // Break loop
            return nil
        default:
            let msg = String(cString: pcap_geterr(handle))
            throw CaptureError.captureError(msg)
        }
    }

    /// Signal the capture loop to stop.
    func breakLoop() {
        pcap_breakloop(handle)
    }

    /// List available network interfaces.
    static func availableInterfaces() throws -> [String] {
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        var alldevs: UnsafeMutablePointer<pcap_if_t>?

        guard pcap_findalldevs(&alldevs, &errbuf) == 0 else {
            throw CaptureError.captureError(
                String(decoding: errbuf.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }, as: UTF8.self)
            )
        }

        var names: [String] = []
        var dev = alldevs
        while let d = dev {
            names.append(String(cString: d.pointee.name))
            dev = d.pointee.next
        }

        pcap_freealldevs(alldevs)
        return names
    }
}
