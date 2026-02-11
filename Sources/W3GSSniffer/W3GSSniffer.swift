import Foundation

/// Live W3GS packet sniffer that captures from a local network interface
/// and streams parsed events via ``AsyncThrowingStream``.
public final class W3GSSniffer: Sendable {
    private let configuration: CaptureConfiguration

    /// Create a sniffer with full capture configuration.
    public init(configuration: CaptureConfiguration) {
        self.configuration = configuration
    }

    /// Create a sniffer for the given interface with default settings.
    public convenience init(interface: String) {
        self.init(configuration: CaptureConfiguration(interface: interface))
    }

    /// A stream of parsed W3GS events from live packet capture.
    ///
    /// The stream opens a libpcap capture session and yields events as they arrive.
    /// Cancel the consuming `Task` to stop the capture.
    ///
    /// Requires root privileges or `access_bpf` group membership.
    public var events: AsyncThrowingStream<W3GSEvent, Error> {
        let config = self.configuration
        return AsyncThrowingStream { continuation in
            let task = Task.detached {
                let source: PacketSource
                do {
                    source = try PacketSource.live(configuration: config)
                } catch {
                    continuation.finish(throwing: error)
                    return
                }

                let parser = W3GSParser()

                continuation.onTermination = { @Sendable _ in
                    source.breakLoop()
                }

                while !Task.isCancelled {
                    let packet: CapturedPacket?
                    do {
                        packet = try source.nextPacket()
                    } catch {
                        continuation.finish(throwing: error)
                        return
                    }

                    guard let pkt = packet else { continue } // timeout, retry

                    let events = parser.parse(packetData: pkt.data, timestamp: pkt.timestamp)
                    for event in events {
                        continuation.yield(event)
                    }
                }
                continuation.finish()
            }

            continuation.onTermination = { @Sendable _ in
                task.cancel()
            }
        }
    }

    /// List available network interfaces for capture.
    public static func availableInterfaces() throws -> [String] {
        try PacketSource.availableInterfaces()
    }
}
