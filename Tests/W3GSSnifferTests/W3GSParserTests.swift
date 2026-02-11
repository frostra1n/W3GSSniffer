import Foundation
import Testing

@testable import W3GSSniffer

let testTimestamp = PacketTimestamp(seconds: 1_700_000_000, microseconds: 0)

// MARK: - Packet building helpers

/// Build an Ethernet + IPv4 + TCP frame wrapping the given TCP payload.
func buildFrame(tcpPayload: Data) -> Data {
    // Ethernet header: 14 bytes (dst MAC 6 + src MAC 6 + EtherType 2)
    var frame = Data(repeating: 0, count: 6) // dst MAC
    frame.append(Data(repeating: 0, count: 6)) // src MAC
    frame.append(contentsOf: [0x08, 0x00]) // EtherType = IPv4

    // IPv4 header: 20 bytes (IHL=5, protocol=TCP=6)
    let ipLen = UInt16(20 + 20 + tcpPayload.count)
    var ip = Data(repeating: 0, count: 20)
    ip[0] = 0x45 // version 4, IHL 5
    ip[2] = UInt8(ipLen >> 8)
    ip[3] = UInt8(ipLen & 0xFF)
    ip[9] = 6 // protocol = TCP
    frame.append(ip)

    // TCP header: 20 bytes (data offset = 5)
    var tcp = Data(repeating: 0, count: 20)
    tcp[12] = 0x50 // data offset = 5 (20 bytes)
    frame.append(tcp)

    // TCP payload
    frame.append(tcpPayload)

    return frame
}

/// Build a W3GS message with header, ID, and payload.
func buildW3GSMessage(id: UInt8, payload: Data) -> Data {
    let totalLen = UInt16(4 + payload.count)
    var msg = Data()
    msg.append(0xF7) // W3GS header
    msg.append(id)
    msg.append(UInt8(totalLen & 0xFF))
    msg.append(UInt8(totalLen >> 8))
    msg.append(payload)
    return msg
}

/// Build a full Ethernet frame containing one W3GS message.
func buildW3GSFrame(messageID: UInt8, messagePayload: Data) -> Data {
    let w3gs = buildW3GSMessage(id: messageID, payload: messagePayload)
    return buildFrame(tcpPayload: w3gs)
}

// MARK: - PlayerInfo tests

@Test func parsesPlayerInfo() {
    // PlayerInfo payload: 4 bytes of prefix data + playerID + null-terminated name
    var payload = Data(repeating: 0, count: 4) // prefix
    payload.append(7) // playerID
    payload.append(contentsOf: "TestPlayer".utf8)
    payload.append(0x00)

    let frame = buildW3GSFrame(messageID: 0x06, messagePayload: payload)
    let parser = W3GSParser()
    let events = parser.parse(packetData: frame, timestamp: testTimestamp)

    #expect(events.count == 1)
    if case .playerJoined(let id, let name, _) = events.first {
        #expect(id == 7)
        #expect(name == "TestPlayer")
    } else {
        Issue.record("Expected playerJoined event")
    }
}

@Test func rejectsShortPlayerInfo() {
    // Too short to contain playerID + name
    let payload = Data([0, 0, 0, 0, 5]) // only 5 bytes, no name
    let frame = buildW3GSFrame(messageID: 0x06, messagePayload: payload)
    let parser = W3GSParser()
    let events = parser.parse(packetData: frame, timestamp: testTimestamp)
    #expect(events.isEmpty)
}

// MARK: - SlotInfo tests

@Test func parsesSlotInfo() {
    // SlotInfo: [2 bytes] [count] [9-byte entries...]
    var payload = Data([0x00, 0x00]) // first 2 bytes
    payload.append(2) // 2 entries

    // Entry 1: occupied, team 0, color 1
    var entry1 = Data(repeating: 0, count: 9)
    entry1[0] = 3  // playerID
    entry1[2] = 2  // status = SLOT_OCCUPIED
    entry1[4] = 0  // team
    entry1[5] = 1  // color
    payload.append(entry1)

    // Entry 2: occupied, team 1, color 5
    var entry2 = Data(repeating: 0, count: 9)
    entry2[0] = 5  // playerID
    entry2[2] = 2  // status = SLOT_OCCUPIED
    entry2[4] = 1  // team
    entry2[5] = 5  // color
    payload.append(entry2)

    let frame = buildW3GSFrame(messageID: 0x09, messagePayload: payload)
    let parser = W3GSParser()
    let events = parser.parse(packetData: frame, timestamp: testTimestamp)

    #expect(events.count == 1)
    if case .slotUpdate(let slots, _) = events.first {
        #expect(slots.count == 2)
        #expect(slots[0] == SlotEntry(playerID: 3, team: 0, color: 1))
        #expect(slots[1] == SlotEntry(playerID: 5, team: 1, color: 5))
    } else {
        Issue.record("Expected slotUpdate event")
    }
}

@Test func filtersBotTeamSlots() {
    var payload = Data([0x00, 0x00])
    payload.append(2)

    // Entry 1: occupied, normal team
    var entry1 = Data(repeating: 0, count: 9)
    entry1[0] = 3
    entry1[2] = 2 // occupied
    entry1[4] = 0 // normal team
    entry1[5] = 1
    payload.append(entry1)

    // Entry 2: occupied, bot team (12)
    var entry2 = Data(repeating: 0, count: 9)
    entry2[0] = 99
    entry2[2] = 2  // occupied
    entry2[4] = 12 // bot team
    entry2[5] = 0
    payload.append(entry2)

    let frame = buildW3GSFrame(messageID: 0x09, messagePayload: payload)
    let parser = W3GSParser()
    let events = parser.parse(packetData: frame, timestamp: testTimestamp)

    if case .slotUpdate(let slots, _) = events.first {
        #expect(slots.count == 1)
        #expect(slots[0].playerID == 3)
    } else {
        Issue.record("Expected slotUpdate event")
    }
}

@Test func filtersEmptySlots() {
    var payload = Data([0x00, 0x00])
    payload.append(1)

    // Entry: empty slot (status = 0)
    var entry = Data(repeating: 0, count: 9)
    entry[0] = 0
    entry[2] = 0 // status = empty
    entry[4] = 0
    entry[5] = 0
    payload.append(entry)

    let frame = buildW3GSFrame(messageID: 0x09, messagePayload: payload)
    let parser = W3GSParser()
    let events = parser.parse(packetData: frame, timestamp: testTimestamp)

    if case .slotUpdate(let slots, _) = events.first {
        #expect(slots.isEmpty)
    } else {
        Issue.record("Expected slotUpdate event")
    }
}

// MARK: - PlayerLeave tests

@Test func parsesPlayerLeave() {
    let payload = Data([42]) // playerID = 42
    let frame = buildW3GSFrame(messageID: 0x21, messagePayload: payload)
    let parser = W3GSParser()
    let events = parser.parse(packetData: frame, timestamp: testTimestamp)

    #expect(events.count == 1)
    if case .playerLeft(let id, _) = events.first {
        #expect(id == 42)
    } else {
        Issue.record("Expected playerLeft event")
    }
}

// MARK: - Chat tests

/// Build a ChatFromHost W3GS payload.
/// Layout: [rcptCount] [recipients...] [senderID] [msgFlag] [msgData...]
func buildChatPayload(senderID: UInt8, flag: UInt8, text: String, recipients: [UInt8] = [1]) -> Data {
    var payload = Data()
    payload.append(UInt8(recipients.count))
    payload.append(contentsOf: recipients)
    payload.append(senderID)
    payload.append(flag)

    if flag == 0x20 {
        // MSG_CHAT_EXTRA: 4-byte scope prefix
        payload.append(Data(repeating: 0, count: 4))
    }

    payload.append(contentsOf: text.utf8)
    payload.append(0x00)
    return payload
}

@Test func parsesRegularChat() {
    let chatPayload = buildChatPayload(senderID: 5, flag: 0x10, text: "Hello everyone")
    let frame = buildW3GSFrame(messageID: 0x0F, messagePayload: chatPayload)
    let parser = W3GSParser()
    let events = parser.parse(packetData: frame, timestamp: testTimestamp)

    #expect(events.count == 1)
    if case .chat(let content, _) = events.first {
        if case .message(let sid, let text) = content {
            #expect(sid == 5)
            #expect(text == "Hello everyone")
        } else {
            Issue.record("Expected .message chat content")
        }
    } else {
        Issue.record("Expected chat event")
    }
}

@Test func parsesChatExtraFlag() {
    let chatPayload = buildChatPayload(senderID: 3, flag: 0x20, text: "Extra message")
    let frame = buildW3GSFrame(messageID: 0x0F, messagePayload: chatPayload)
    let parser = W3GSParser()
    let events = parser.parse(packetData: frame, timestamp: testTimestamp)

    #expect(events.count == 1)
    if case .chat(let content, _) = events.first {
        if case .message(_, let text) = content {
            #expect(text == "Extra message")
        } else {
            Issue.record("Expected .message chat content")
        }
    } else {
        Issue.record("Expected chat event")
    }
}

@Test func parsesRoomStats() {
    let text = "PlayerOne room stats [ 1500 points | 200 games | 55% winrate | 3% disconnects ]"
    let chatPayload = buildChatPayload(senderID: 1, flag: 0x10, text: text)
    let frame = buildW3GSFrame(messageID: 0x0F, messagePayload: chatPayload)
    let parser = W3GSParser()
    let events = parser.parse(packetData: frame, timestamp: testTimestamp)

    #expect(events.count == 1)
    if case .chat(let content, _) = events.first {
        if case .roomStats(let stats) = content {
            #expect(stats.name == "PlayerOne")
            #expect(stats.points == 1500)
            #expect(stats.games == 200)
            #expect(stats.winRatePercent == 55)
            #expect(stats.disconnectPercent == 3)
        } else {
            Issue.record("Expected .roomStats chat content")
        }
    } else {
        Issue.record("Expected chat event")
    }
}

@Test func parsesPointsResponse() {
    let text = "Alice [1500], Bob [1400], Charlie [1300]"
    let chatPayload = buildChatPayload(senderID: 1, flag: 0x10, text: text)
    let frame = buildW3GSFrame(messageID: 0x0F, messagePayload: chatPayload)
    let parser = W3GSParser()
    let events = parser.parse(packetData: frame, timestamp: testTimestamp)

    #expect(events.count == 1)
    if case .chat(let content, _) = events.first {
        if case .pointsResponse(let entries) = content {
            #expect(entries.count == 3)
            #expect(entries[0] == PointsEntry(name: "Alice", points: 1500))
            #expect(entries[1] == PointsEntry(name: "Bob", points: 1400))
            #expect(entries[2] == PointsEntry(name: "Charlie", points: 1300))
        } else {
            Issue.record("Expected .pointsResponse chat content")
        }
    } else {
        Issue.record("Expected chat event")
    }
}

// MARK: - Network layer edge cases

@Test func rejectsNonIPv4Frame() {
    // Build a frame with EtherType = 0x86DD (IPv6)
    var frame = Data(repeating: 0, count: 6 + 6) // MACs
    frame.append(contentsOf: [0x86, 0xDD]) // IPv6
    frame.append(Data(repeating: 0, count: 40)) // pad to minimum

    let parser = W3GSParser()
    let events = parser.parse(packetData: frame, timestamp: testTimestamp)
    #expect(events.isEmpty)
}

@Test func rejectsNonTCPFrame() {
    // Build IPv4 frame with protocol = UDP (17)
    var frame = Data(repeating: 0, count: 6 + 6)
    frame.append(contentsOf: [0x08, 0x00]) // IPv4
    var ip = Data(repeating: 0, count: 20)
    ip[0] = 0x45
    ip[9] = 17 // UDP
    frame.append(ip)
    frame.append(Data(repeating: 0, count: 22)) // pad

    let parser = W3GSParser()
    let events = parser.parse(packetData: frame, timestamp: testTimestamp)
    #expect(events.isEmpty)
}

@Test func rejectsTooShortFrame() {
    let frame = Data(repeating: 0, count: 20) // way too short
    let parser = W3GSParser()
    let events = parser.parse(packetData: frame, timestamp: testTimestamp)
    #expect(events.isEmpty)
}

@Test func rejectsNonW3GSPayload() {
    // TCP payload that doesn't start with 0xF7
    let payload = Data([0x00, 0x01, 0x02, 0x03, 0x04])
    let frame = buildFrame(tcpPayload: payload)
    let parser = W3GSParser()
    let events = parser.parse(packetData: frame, timestamp: testTimestamp)
    #expect(events.isEmpty)
}

// MARK: - Multiple messages in one payload

@Test func parsesMultipleW3GSMessages() {
    // Two W3GS messages in one TCP payload
    var playerPayload = Data(repeating: 0, count: 4)
    playerPayload.append(2) // playerID
    playerPayload.append(contentsOf: "Hero".utf8)
    playerPayload.append(0x00)
    let msg1 = buildW3GSMessage(id: 0x06, payload: playerPayload)

    let leavePayload = Data([10]) // playerID = 10
    let msg2 = buildW3GSMessage(id: 0x21, payload: leavePayload)

    var combined = msg1
    combined.append(msg2)

    let frame = buildFrame(tcpPayload: combined)
    let parser = W3GSParser()
    let events = parser.parse(packetData: frame, timestamp: testTimestamp)

    #expect(events.count == 2)
    if case .playerJoined(let id, let name, _) = events[0] {
        #expect(id == 2)
        #expect(name == "Hero")
    } else {
        Issue.record("Expected playerJoined")
    }
    if case .playerLeft(let id, _) = events[1] {
        #expect(id == 10)
    } else {
        Issue.record("Expected playerLeft")
    }
}

// MARK: - W3GS message framing edge cases

@Test func handlesTruncatedW3GSMessage() {
    // W3GS message claims length 100 but only 10 bytes available
    var payload = Data()
    payload.append(0xF7)
    payload.append(0x06) // PlayerInfo
    payload.append(100)  // length low byte
    payload.append(0)    // length high byte
    payload.append(Data(repeating: 0, count: 6)) // only 10 bytes total

    let frame = buildFrame(tcpPayload: payload)
    let parser = W3GSParser()
    let events = parser.parse(packetData: frame, timestamp: testTimestamp)
    #expect(events.isEmpty)
}

@Test func handlesUnknownMessageID() {
    let payload = Data([0x01, 0x02, 0x03])
    let frame = buildW3GSFrame(messageID: 0xFF, messagePayload: payload)
    let parser = W3GSParser()
    let events = parser.parse(packetData: frame, timestamp: testTimestamp)
    #expect(events.isEmpty)
}

// MARK: - PacketTimestamp tests

@Test func timestampConvertsToDate() {
    let ts = PacketTimestamp(seconds: 1_700_000_000, microseconds: 500_000)
    let expected = Date(timeIntervalSince1970: 1_700_000_000.5)
    #expect(ts.date == expected)
}

@Test func timestampFormatsTimeString() {
    let ts = PacketTimestamp(seconds: 0, microseconds: 0)
    let str = ts.timeString
    // Should be some valid HH:MM:SS format (exact value depends on timezone)
    #expect(str.count == 8)
    #expect(str.contains(":"))
}
