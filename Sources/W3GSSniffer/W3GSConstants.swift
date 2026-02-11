/// W3GS protocol constants.
enum W3GSConstants {
    /// Magic header byte for all W3GS packets.
    static let header: UInt8 = 0xF7

    // MARK: - Message IDs

    static let playerInfo: UInt8 = 0x06
    static let slotInfo: UInt8 = 0x09
    static let chatFromHost: UInt8 = 0x0F
    static let playerLeave: UInt8 = 0x21

    // MARK: - SlotInfo constants

    static let slotEntrySize = 9
    static let slotOccupied: UInt8 = 2
    static let botTeam: UInt8 = 12

    // MARK: - Chat message flags

    static let msgChat: UInt8 = 0x10
    static let msgChatExtra: UInt8 = 0x20
}
