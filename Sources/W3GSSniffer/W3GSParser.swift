import Foundation

/// Stateless parser that converts raw packet bytes into ``W3GSEvent`` values.
public struct W3GSParser: Sendable {
    public init() {}

    // MARK: - Public API

    /// Parse a raw Ethernet frame and return any W3GS events found inside.
    public func parse(packetData: Data, timestamp: PacketTimestamp) -> [W3GSEvent] {
        guard let tcpPayload = extractTCPPayload(from: packetData) else {
            return []
        }

        var events: [W3GSEvent] = []
        for (messageID, payload) in extractW3GSMessages(from: tcpPayload) {
            switch messageID {
            case W3GSConstants.playerInfo:
                if let event = parsePlayerInfo(payload, timestamp: timestamp) {
                    events.append(event)
                }
            case W3GSConstants.slotInfo:
                if let event = parseSlotInfo(payload, timestamp: timestamp) {
                    events.append(event)
                }
            case W3GSConstants.chatFromHost:
                if let event = parseChat(payload, timestamp: timestamp) {
                    events.append(event)
                }
            case W3GSConstants.playerLeave:
                if let event = parsePlayerLeave(payload, timestamp: timestamp) {
                    events.append(event)
                }
            default:
                break
            }
        }
        return events
    }

    // MARK: - Network layer extraction

    /// Extract TCP payload from a raw Ethernet frame.
    /// Returns `nil` if the frame is not IPv4/TCP or is too short.
    func extractTCPPayload(from packetData: Data) -> Data? {
        guard packetData.count >= 54 else { return nil }

        // Ethernet: EtherType at offset 12 (big-endian)
        let ethType = UInt16(packetData[12]) << 8 | UInt16(packetData[13])
        guard ethType == 0x0800 else { return nil }

        // IPv4: IHL at offset 14, protocol at offset 23
        let ipOffset = 14
        let ihl = Int(packetData[ipOffset] & 0x0F) * 4
        guard packetData[ipOffset + 9] == 6 else { return nil } // TCP only

        // TCP: header length from data offset field
        let tcpOffset = ipOffset + ihl
        guard tcpOffset + 13 <= packetData.count else { return nil }
        let tcpHeaderLen = Int(packetData[tcpOffset + 12] >> 4) * 4
        let payloadStart = tcpOffset + tcpHeaderLen
        guard payloadStart <= packetData.count else { return nil }

        return packetData[payloadStart...]
    }

    /// Iterate W3GS messages within a TCP payload.
    /// Each message starts with 0xF7, followed by message ID and UInt16LE length.
    func extractW3GSMessages(from payload: Data) -> [(UInt8, Data)] {
        var results: [(UInt8, Data)] = []
        var pos = payload.startIndex

        while pos + 4 <= payload.endIndex {
            guard payload[pos] == W3GSConstants.header else { break }
            let messageID = payload[pos + 1]
            let msgLen = Int(payload[pos + 2]) | (Int(payload[pos + 3]) << 8)
            guard msgLen >= 4, pos + msgLen <= payload.endIndex else { break }
            let messagePayload = payload[(pos + 4) ..< (pos + msgLen)]
            results.append((messageID, Data(messagePayload)))
            pos += msgLen
        }

        return results
    }

    // MARK: - Message parsers

    /// Parse a PlayerInfo message.
    /// Layout: `[4 bytes header prefix] [playerID] [name (null-terminated)] ...`
    /// The payload here starts after the 4-byte W3GS header, so:
    /// payload[4] = playerID, payload[5..null] = name.
    func parsePlayerInfo(_ payload: Data, timestamp: PacketTimestamp) -> W3GSEvent? {
        guard payload.count >= 6 else { return nil }
        let playerID = payload[payload.startIndex + 4]
        let nameStart = payload.startIndex + 5
        guard let nullIndex = payload[nameStart...].firstIndex(of: 0x00),
              nullIndex > nameStart else {
            return nil
        }
        let name = String(data: payload[nameStart ..< nullIndex], encoding: .utf8)
            ?? String(data: payload[nameStart ..< nullIndex], encoding: .ascii)
            ?? ""
        return .playerJoined(id: playerID, name: name, timestamp: timestamp)
    }

    /// Parse a SlotInfo message.
    /// Layout: payload[2] = entry count, then 9-byte entries starting at payload[3].
    func parseSlotInfo(_ payload: Data, timestamp: PacketTimestamp) -> W3GSEvent? {
        guard payload.count >= 3 else { return nil }
        let numEntries = Int(payload[payload.startIndex + 2])
        let entriesStart = payload.startIndex + 3
        guard entriesStart + numEntries * W3GSConstants.slotEntrySize <= payload.endIndex else {
            return nil
        }

        var slots: [SlotEntry] = []
        for i in 0 ..< numEntries {
            let off = entriesStart + i * W3GSConstants.slotEntrySize
            let pid = payload[off]
            let status = payload[off + 2]
            let team = payload[off + 4]
            let color = payload[off + 5]
            if status == W3GSConstants.slotOccupied && team != W3GSConstants.botTeam {
                slots.append(SlotEntry(playerID: pid, team: team, color: color))
            }
        }
        return .slotUpdate(slots: slots, timestamp: timestamp)
    }

    /// Parse a PlayerLeave message. payload[0] = leaving player ID.
    func parsePlayerLeave(_ payload: Data, timestamp: PacketTimestamp) -> W3GSEvent? {
        guard payload.count >= 1 else { return nil }
        return .playerLeft(id: payload[payload.startIndex], timestamp: timestamp)
    }

    /// Parse a ChatFromHost message.
    /// Layout: [recipientCount] [recipients...] [senderID] [msgFlag] [msgData...]
    func parseChat(_ payload: Data, timestamp: PacketTimestamp) -> W3GSEvent? {
        guard payload.count >= 3 else { return nil }
        let rcptCount = Int(payload[payload.startIndex])
        let base = payload.startIndex + 1 + rcptCount
        guard base + 2 <= payload.endIndex else { return nil }

        let senderID = payload[base]
        let msgFlag = payload[base + 1]
        let msgData = payload[(base + 2)...]

        guard let text = extractChatText(flag: msgFlag, data: msgData) else {
            return nil
        }

        let content = classifyChat(text: text, senderID: senderID)
        return .chat(content: content, timestamp: timestamp)
    }

    // MARK: - Chat helpers

    /// Extract the message string from chat data based on the flag type.
    func extractChatText(flag: UInt8, data: Data) -> String? {
        let raw: Data
        switch flag {
        case W3GSConstants.msgChat:
            raw = Data(data)
        case W3GSConstants.msgChatExtra:
            guard data.count >= 4 else { return nil }
            raw = Data(data.dropFirst(4)) // skip 4-byte scope field
        default:
            return nil
        }

        let end = raw.firstIndex(of: 0x00) ?? raw.endIndex
        return String(data: raw[raw.startIndex ..< end], encoding: .utf8)
            ?? String(data: raw[raw.startIndex ..< end], encoding: .ascii)
    }

    /// Classify a chat message as room stats, points response, or plain message.
    func classifyChat(text: String, senderID: UInt8) -> ChatContent {
        // 1) Room stats announcement
        if let stats = parseRoomStats(text) {
            return .roomStats(stats)
        }

        // 2) !points response
        if let entries = parsePointsResponse(text) {
            return .pointsResponse(entries)
        }

        // 3) Regular message
        return .message(senderID: senderID, text: text)
    }

    /// Try to parse a room stats announcement.
    /// Format: `PlayerName room stats [ 1500 points | 100 games | 55% winrate | 3% disconnects ]`
    private func parseRoomStats(_ text: String) -> PlayerStats? {
        let pattern = /(.+?)\s+room stats\s+\[\s*(\d+)\s+points\s*\|\s*(\d+)\s+games\s*\|\s*(\d+)%\s+winrate\s*\|\s*(\d+)%\s+disconnects\s*\]/
        guard let match = text.firstMatch(of: pattern) else { return nil }
        guard let points = Int(match.2),
              let games = Int(match.3),
              let winRate = Int(match.4),
              let dc = Int(match.5) else { return nil }
        return PlayerStats(
            name: String(match.1),
            points: points,
            games: games,
            winRatePercent: winRate,
            disconnectPercent: dc
        )
    }

    /// Try to parse a `!points` response.
    /// Format: `Name1 [1500], Name2 [1400], ...`
    private func parsePointsResponse(_ text: String) -> [PointsEntry]? {
        let bracketPattern = /\[\d+\]/
        guard text.firstMatch(of: bracketPattern) != nil else { return nil }

        let entryPattern = /(.+?)\s+\[(\d+)\]/
        var entries: [PointsEntry] = []
        for part in text.split(separator: ", ") {
            if let match = String(part).firstMatch(of: entryPattern),
               let points = Int(match.2) {
                entries.append(PointsEntry(name: String(match.1), points: points))
            }
        }
        guard !entries.isEmpty else { return nil }
        return entries
    }
}
