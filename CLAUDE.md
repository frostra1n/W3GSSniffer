# W3GSSniffer

Swift Package library that captures W3GS (Warcraft 3 Game Server) packets from a local network interface via libpcap and streams parsed events through `AsyncThrowingStream`.

## Build & test

```
swift build
swift test
```

Live capture requires root or `access_bpf` group membership. Tests use crafted byte arrays and don't require capture permissions.

## Architecture

- **CLibpcap** — System library target bridging libpcap (ships with macOS SDK, no external deps)
- **W3GSSniffer** — Library target with all parsing and capture logic
- **W3GSSnifferTests** — Parser tests using Swift Testing framework

## Key files

- `W3GSConstants.swift` — Protocol constants (header byte `0xF7`, message IDs, slot sizes)
- `W3GSEvent.swift` — Public types: `W3GSEvent`, `SlotEntry`, `PlayerStats`, `PointsEntry`, `ChatContent`, `PacketTimestamp`
- `W3GSParser.swift` — Stateless parser: raw Ethernet frame bytes → `[W3GSEvent]`. Extracts TCP payload, iterates W3GS messages, parses each message type
- `PacketSource.swift` — Internal libpcap wrapper: `pcap_open_live`, `pcap_next_ex`, `pcap_breakloop`, `pcap_findalldevs`. Also defines `CaptureConfiguration` and `CaptureError`
- `W3GSSniffer.swift` — Public entry point: `W3GSSniffer(interface:)` exposes `events: AsyncThrowingStream<W3GSEvent, Error>`

## Design decisions

- **Stateless parsing** — The library only parses and streams events. All state tracking (players, points, slots, local player identification) is the consumer's responsibility.
- **No external dependencies** — Uses libpcap from the macOS SDK via a system library target.
- **Pull-based capture loop** — `PacketSource.nextPacket()` calls `pcap_next_ex` with a 100ms timeout, checking `Task.isCancelled` between calls for cooperative cancellation.

## W3GS protocol notes

- Every W3GS message starts with `0xF7`, followed by a message ID byte and a UInt16LE length
- Multiple W3GS messages can appear in a single TCP payload
- Message types parsed: `PlayerInfo (0x06)`, `SlotInfo (0x09)`, `ChatFromHost (0x0F)`, `PlayerLeave (0x21)`
- Chat messages are classified as room stats, `!points` responses, or plain messages via regex
- The local player receives no `PlayerInfo` packet; consumers must infer their identity from the `!points` response (the one name not matching any known remote player)
