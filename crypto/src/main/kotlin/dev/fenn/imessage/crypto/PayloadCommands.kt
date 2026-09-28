package dev.fenn.imessage.crypto

/**
 * Payload command numbers — the `c` field of the outer envelope (spec §4.1) — on the
 * madrid / SMS-alloy topics (spec §5.1). Wire facts; these are courier-message commands,
 * not the APNs framing commands of [CourierFrame].
 *
 * Only the numbers both sources agree on are constants here. The spec additionally records
 * single-source numbers (113, 120, 122, 131, 138, 160, 103, 196, 104, 142, 146, 149 —
 * TODO(capture) C36); none of those are wired until a capture confirms them.
 */
object PayloadCommands {

    /** iMessage payload (text, reactions, typing, effects) — spec §5.1/§5.2. */
    const val PAYLOAD = 100

    const val DELIVERED = 101

    const val READ = 102

    const val CERTIFIED_DELIVERY_RECEIPT = 109

    const val MARK_UNREAD = 111

    /** Edit and unsend (spec §5.4). */
    const val EDIT = 118

    /** Peer cache invalidate / new-device notice. */
    const val PEER_CACHE_INVALIDATE = 130

    /** Incoming SMS / MMS forwarded from a real phone. */
    const val SMS_INCOMING = 140
    const val MMS_INCOMING = 141

    /** SMS / MMS sent by this client (reflected). */
    const val SMS_REFLECTED = 143
    const val MMS_REFLECTED = 144

    /** SMS relay enable / toggle confirm. */
    const val SMS_RELAY_CONFIRM = 145

    /** Read-on-device — the SMS variant of [READ]. */
    const val SMS_READ_ON_DEVICE = 147

    /** Profile / settings changes. */
    const val PROFILE = 180

    /** Chat delete (recoverable metadata rides under 182). */
    const val CHAT_DELETE = 181
    const val CHAT_DELETE_METADATA = 182

    /** Group events (spec §5.7). */
    const val GROUP_EVENT = 190

    /** Send-time ack: echoes the message UUID with a per-device status (spec §5.6). */
    const val SEND_ACK = 255

    /** APNs-tunnel HTTP request / response (spec §5.1, both sources). */
    const val TUNNEL_REQUEST = 96
    const val TUNNEL_RESPONSE = 97
}
