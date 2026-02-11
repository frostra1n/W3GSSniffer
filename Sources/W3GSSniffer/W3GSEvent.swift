import Foundation

/// Timestamp from a captured packet's pcap header.
public struct PacketTimestamp: Sendable, Equatable {
    public let seconds: UInt32
    public let microseconds: UInt32

    public init(seconds: UInt32, microseconds: UInt32) {
        self.seconds = seconds
        self.microseconds = microseconds
    }

    /// Convert to a Foundation `Date`.
    public var date: Date {
        Date(timeIntervalSince1970: TimeInterval(seconds) + TimeInterval(microseconds) / 1_000_000)
    }

    /// Formatted as `HH:MM:SS`.
    public var timeString: String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        return formatter.string(from: date)
    }
}

/// A single occupied slot entry from a SlotInfo message.
public struct SlotEntry: Sendable, Equatable {
    public let playerID: UInt8
    public let team: UInt8
    public let color: UInt8

    public init(playerID: UInt8, team: UInt8, color: UInt8) {
        self.playerID = playerID
        self.team = team
        self.color = color
    }
}

/// Room stats announced for a player on join.
public struct PlayerStats: Sendable, Equatable {
    public let name: String
    public let points: Int
    public let games: Int
    public let winRatePercent: Int
    public let disconnectPercent: Int

    public init(name: String, points: Int, games: Int, winRatePercent: Int, disconnectPercent: Int) {
        self.name = name
        self.points = points
        self.games = games
        self.winRatePercent = winRatePercent
        self.disconnectPercent = disconnectPercent
    }
}

/// A single entry from a `!points` response.
public struct PointsEntry: Sendable, Equatable {
    public let name: String
    public let points: Int

    public init(name: String, points: Int) {
        self.name = name
        self.points = points
    }
}

/// The content parsed from a ChatFromHost message.
public enum ChatContent: Sendable, Equatable {
    /// Individual room stats announcement (auto-sent on player join).
    case roomStats(PlayerStats)
    /// Response to the `!points` command listing all players' points.
    case pointsResponse([PointsEntry])
    /// A regular chat message.
    case message(senderID: UInt8, text: String)
}

/// An event parsed from a W3GS packet.
public enum W3GSEvent: Sendable, Equatable {
    /// A remote player joined (PlayerInfo message).
    case playerJoined(id: UInt8, name: String, timestamp: PacketTimestamp)
    /// A player left the game (PlayerLeave message).
    case playerLeft(id: UInt8, timestamp: PacketTimestamp)
    /// Slot layout changed (SlotInfo message). Contains only occupied, non-bot slots.
    case slotUpdate(slots: [SlotEntry], timestamp: PacketTimestamp)
    /// A chat message was received (ChatFromHost message).
    case chat(content: ChatContent, timestamp: PacketTimestamp)
}
