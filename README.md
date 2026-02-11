# W3GSSniffer

Swift library that sniffs Warcraft 3 (W3GS) game lobby packets off a local network interface using libpcap and streams parsed events via `AsyncThrowingStream`.

## What it does

Captures and parses these W3GS message types from live traffic:

- **PlayerInfo** — player joins
- **SlotInfo** — slot layout changes
- **ChatFromHost** — chat messages, room stats, `!points` responses
- **PlayerLeave** — player departures

The library is stateless — it only parses packets and emits events. Tracking players, points, and game state is up to you.

## Requirements

- macOS 13+
- Swift 6.0+
- Root or `access_bpf` group membership for live capture

## Usage

```swift
let sniffer = W3GSSniffer(interface: "en0")

for try await event in sniffer.events {
    switch event {
    case .playerJoined(let id, let name, _):
        print("\(name) joined (id: \(id))")
    case .playerLeft(let id, _):
        print("Player \(id) left")
    case .slotUpdate(let slots, _):
        print("Slots: \(slots.count) occupied")
    case .chat(let content, _):
        print("Chat: \(content)")
    }
}
```

## Build & test

```
swift build
swift test
```

Tests use crafted byte arrays and don't need capture permissions.
