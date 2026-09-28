package dev.fenn.imessage.courier

import dev.fenn.imessage.codec.BpDict
import dev.fenn.imessage.codec.BpString
import dev.fenn.imessage.codec.BpValue
import dev.fenn.imessage.codec.Bplist
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * Courier command builders over the §3.2 legacy frame: the per-command field-id tables of
 * spec §3.3 (C45, closed in rev 12). Every table recorded there is implemented; where the
 * two extracted sources disagree (C57, §7 item 21) the differing shape is an explicit
 * parameter defaulting to what the section's prose states — never a silent choice.
 *
 * Note (rev 12): payload command 160 is a `c` value inside command-10 plists, NOT a frame
 * command — the payload layer owns it; nothing here builds it.
 */
object CourierCommands {

    // --- connect (7) field ids, sent token/state/flags/cert/nonce/signature (§3.3) --------
    const val CONNECT_FIELD_TOKEN = 1
    const val CONNECT_FIELD_STATE = 2
    const val CONNECT_FIELD_FLAGS = 5
    const val CONNECT_FIELD_CERTIFICATE = 12
    const val CONNECT_FIELD_NONCE = 13
    const val CONNECT_FIELD_SIGNATURE = 14
    /** Rust-only extra: hardcoded version identifier, value 9 (§3.3, C57). */
    const val CONNECT_FIELD_RUST_VERSION = 0x10
    const val CONNECT_RUST_VERSION_VALUE = 9

    /** Connect state byte (§3.3: "a state byte (1)"). */
    const val CONNECT_STATE = 1

    /**
     * Connection flags (§3.3, C57): both sources' base reads the same value `0b1000001` =
     * 0x41; only Go adds the `0b100` bit marking a root connection. That bit is explicit in
     * [CONNECT_FLAG_ROOT] — default off (the plain registered-device connection).
     */
    const val CONNECT_FLAGS_BASE = 0x41
    const val CONNECT_FLAG_ROOT = 0x04

    // --- send message (10) field ids (§3.3, outgoing agreed) ------------------------------
    const val SEND_FIELD_TOPIC = 1
    const val SEND_FIELD_TOKEN = 2
    const val SEND_FIELD_PAYLOAD = 3
    const val SEND_FIELD_MESSAGE_ID = 4

    // --- send ack (11) field ids (§3.3): 1 token, 4 message id, 8 status ------------------
    const val ACK_FIELD_TOKEN = 1
    const val ACK_FIELD_MESSAGE_ID = 4
    const val ACK_FIELD_STATUS = 8

    // --- set state (20) field ids (§3.3, both sources) ------------------------------------
    const val SET_STATE_FIELD_STATE = 1
    const val SET_STATE_FIELD_INTERVAL = 2
    /** §3.3: the interval field's recorded constant (both sources). */
    const val SET_STATE_INTERVAL = 0x7fffffff

    /** SHA-1 of a topic string — how topics appear on the wire (§3.3 filter, §2.3). */
    fun topicHash(topic: String): ByteArray =
        MessageDigest.getInstance("SHA-1").digest(topic.toByteArray(Charsets.UTF_8))

    /**
     * Filter (9), sent after connect and on topic-set changes (§3.3).
     *
     * Field-set disagreement (C57): [FilterShape.PER_TOPIC_STATES] is the prose's reading —
     * token (1) plus per-state fields enabled (2) / ignored (3) / opportunistic (4) / paused
     * (5), each carrying the SHA-1 topic hashes in that state; [FilterShape.TOPIC_LIST] is
     * the other client's shape — token (1) plus a single topic field (2) listing the
     * subscribed hashes.
     *
     * TODO(capture): the multi-topic field encoding is not recorded — this concatenates the
     * 20-byte digests per field; a real client's filter frame arbitrates.
     */
    enum class FilterShape { PER_TOPIC_STATES, TOPIC_LIST }

    fun filterFrame(
        token: ByteArray,
        enabled: List<ByteArray> = emptyList(),
        ignored: List<ByteArray> = emptyList(),
        opportunistic: List<ByteArray> = emptyList(),
        paused: List<ByteArray> = emptyList(),
        shape: FilterShape = FilterShape.PER_TOPIC_STATES,
    ): CourierFrame.Frame {
        val fields = ArrayList<CourierFrame.Frame.Field>()
        fields.add(CourierFrame.Frame.Field(1, token))
        when (shape) {
            FilterShape.PER_TOPIC_STATES -> {
                fields.add(CourierFrame.Frame.Field(2, hashes(enabled)))
                fields.add(CourierFrame.Frame.Field(3, hashes(ignored)))
                fields.add(CourierFrame.Frame.Field(4, hashes(opportunistic)))
                fields.add(CourierFrame.Frame.Field(5, hashes(paused)))
            }
            FilterShape.TOPIC_LIST ->
                fields.add(CourierFrame.Frame.Field(2, hashes(enabled + ignored + opportunistic + paused)))
        }
        return CourierFrame.Frame(CourierFrame.FILTER, fields)
    }

    /**
     * Send message (10), outgoing fields agreed (§3.3): topic (1), connect token (2),
     * payload plist (3), message id (4, u32 BE — random in 1..2^31−1, see
     * [CourierClient.newMessageId]). [topic] is the wire form — the SHA-1 of the topic string.
     */
    fun sendFrame(topic: ByteArray, token: ByteArray, payload: ByteArray, messageId: Int): CourierFrame.Frame =
        CourierFrame.Frame(
            CourierFrame.SEND,
            listOf(
                CourierFrame.Frame.Field(SEND_FIELD_TOPIC, topic),
                CourierFrame.Frame.Field(SEND_FIELD_TOKEN, token),
                CourierFrame.Frame.Field(SEND_FIELD_PAYLOAD, payload),
                CourierFrame.Frame.Field(SEND_FIELD_MESSAGE_ID, u32(messageId)),
            ),
        )

    /**
     * Send ack (11) (§3.3): token (1), the acknowledged message id (4), status (8; 0 =
     * accepted, 0x80 = sent-too-early, 0x03 = too large).
     */
    fun ackFrame(token: ByteArray, messageId: Int, status: Int): CourierFrame.Frame =
        CourierFrame.Frame(
            CourierFrame.SEND_ACK,
            listOf(
                CourierFrame.Frame.Field(ACK_FIELD_TOKEN, token),
                CourierFrame.Frame.Field(ACK_FIELD_MESSAGE_ID, u32(messageId)),
                CourierFrame.Frame.Field(ACK_FIELD_STATUS, byteArrayOf(status.toByte())),
            ),
        )

    /** Keepalive (12) / keepalive ack (13): no fields (§3.3). */
    fun keepaliveFrame(): ByteArray = CourierFrame.encode(CourierFrame.KEEPALIVE)

    fun keepaliveAckFrame(): ByteArray = CourierFrame.encode(CourierFrame.KEEPALIVE_ACK)

    /**
     * Set state (20) (§3.3, both sources): state (1, u8) and interval (2) at the recorded
     * constant [SET_STATE_INTERVAL].
     */
    fun setStateFrame(state: Int): CourierFrame.Frame =
        CourierFrame.Frame(
            CourierFrame.SET_STATE,
            listOf(
                CourierFrame.Frame.Field(SET_STATE_FIELD_STATE, byteArrayOf(state.toByte())),
                CourierFrame.Frame.Field(SET_STATE_FIELD_INTERVAL, u32(SET_STATE_INTERVAL)),
            ),
        )

    /**
     * Subscribe-to-channels (29) (§3.3): recorded from one source only with fields 1 index,
     * 2 message (protobuf), 3 token; its response carries a status field 4.
     * TODO(capture) C24 — whether real clients use it; unwired until then.
     */
    fun subscribeChannelsFrame(index: ByteArray, message: ByteArray, token: ByteArray): CourierFrame.Frame =
        CourierFrame.Frame(
            29,
            listOf(
                CourierFrame.Frame.Field(1, index),
                CourierFrame.Frame.Field(2, message),
                CourierFrame.Frame.Field(3, token),
            ),
        )

    // --- tunnel request (96) / tunnel response (97) (spec §2.1) ---------------------------

    /** The header dictionary key inside the tunnel payload (spec §2.1: "the lookup request
     * and its headers travel inside a tunnel payload whose header dictionary is keyed `h`"). */
    const val TUNNEL_HEADERS_KEY = "h"

    /** §2.1: "a 16-byte request UUID" correlates the command-97 response with its request. */
    const val TUNNEL_REQUEST_UUID_BYTES = 16

    /**
     * Frame field ids of the tunnel commands. Spec §2.1 records the field SET — 96: URL,
     * headers, content type, body, 16-byte request UUID; 97: the same request UUID, a status
     * field, the body — but not their ids, so the mapping is caller-supplied and a stale
     * guess fails loudly instead of silently riding along (TODO(capture) C12).
     */
    data class TunnelFieldIds(
        val requestUrl: Int,
        val requestHeaders: Int,
        val requestContentType: Int,
        val requestBody: Int,
        val requestUuid: Int,
        val replyUuid: Int,
        val replyStatus: Int,
        val replyBody: Int,
    )

    /**
     * The command-96 tunnel request (§2.1): one field per recorded item. The headers field
     * carries the header dictionary keyed [TUNNEL_HEADERS_KEY] — a binary plist `{"h": {…}}`.
     */
    fun tunnelRequestFrame(
        url: String,
        headers: Map<String, String>,
        contentType: String,
        body: ByteArray,
        requestUuid: ByteArray,
        ids: TunnelFieldIds,
    ): CourierFrame.Frame {
        require(requestUuid.size == TUNNEL_REQUEST_UUID_BYTES) {
            "tunnel request uuid must be $TUNNEL_REQUEST_UUID_BYTES bytes, got ${requestUuid.size}"
        }
        return CourierFrame.Frame(
            CourierFrame.TUNNEL_REQUEST,
            listOf(
                CourierFrame.Frame.Field(ids.requestUrl, url.toByteArray(Charsets.UTF_8)),
                CourierFrame.Frame.Field(
                    ids.requestHeaders,
                    // binary plist {"h": {header: value, …}}
                    Bplist.encode(
                        BpDict(
                            buildMap {
                                put(
                                    BpString(TUNNEL_HEADERS_KEY),
                                    BpDict(
                                        LinkedHashMap<BpValue, BpValue>().apply {
                                            for ((k, v) in headers) put(BpString(k), BpString(v))
                                        }
                                    ),
                                )
                            }
                        )
                    ),
                ),
                CourierFrame.Frame.Field(ids.requestContentType, contentType.toByteArray(Charsets.UTF_8)),
                CourierFrame.Frame.Field(ids.requestBody, body),
                CourierFrame.Frame.Field(ids.requestUuid, requestUuid),
            ),
        )
    }

    /** The parsed command-97 tunnel response (§2.1): same request UUID, a status field, the body. */
    data class TunnelResponse(val requestUuid: ByteArray, val status: Int, val body: ByteArray)

    fun parseTunnelResponse(frame: CourierFrame.Frame, ids: TunnelFieldIds): TunnelResponse {
        require(frame.command == CourierFrame.TUNNEL_RESPONSE) {
            "command ${frame.command} is not a tunnel response"
        }
        val uuid = frame.field(ids.replyUuid)
            ?: throw IllegalArgumentException("tunnel response without a request-uuid field")
        val status = frame.field(ids.replyStatus)?.let(::u32Value)
            ?: throw IllegalArgumentException("tunnel response without a status field")
        return TunnelResponse(uuid, status, frame.field(ids.replyBody) ?: ByteArray(0))
    }

    // --- connect response (8) -------------------------------------------------------------

    /** Connect-response status values (§3.3): 0 ok; 2 invalid certificate. */
    const val CONNECT_STATUS_OK = 0
    const val CONNECT_STATUS_INVALID_CERT = 2

    /**
     * The connect response (§3.3): status (1) and the 32-byte connect token (3) — the token
     * the client stores and uses in later messages. The other source's extra fields (4 max
     * message size ~4 KiB, 5, 6 capabilities, 8 large-message size ~15 KiB, 10 server
     * timestamp unix ms) are parsed when present; the shape of 5 and 6 is unrecorded, so
     * they stay raw (C57).
     */
    data class ConnectResponse(
        val status: Int,
        val token: ByteArray?,
        val maxMessageSize: Int?,
        val capabilities: ByteArray?,
        val largeMessageSize: Int?,
        val serverTimestampMs: Long?,
        val raw: List<CourierFrame.Frame.Field>,
    ) {
        fun ok(): Boolean = status == CONNECT_STATUS_OK
    }

    fun parseConnectResponse(frame: CourierFrame.Frame): ConnectResponse {
        require(frame.command == CourierFrame.CONNECT_RESPONSE) {
            "command ${frame.command} is not a connect response"
        }
        val status = frame.field(1)?.let { if (it.isEmpty()) null else it[0].toInt() and 0xFF }
            ?: throw IllegalArgumentException("connect response without a status field")
        return ConnectResponse(
            status = status,
            token = frame.field(3),
            maxMessageSize = frame.field(4)?.let(::u32Value),
            capabilities = frame.field(6),
            largeMessageSize = frame.field(8)?.let(::u32Value),
            serverTimestampMs = frame.field(10)?.let(::u64Value),
            raw = frame.fields,
        )
    }

    private fun hashes(topics: List<ByteArray>): ByteArray {
        val out = ByteArrayOutputStream(topics.size * 20)
        for (hash in topics) {
            require(hash.size == 20) { "topic hashes are SHA-1 (20 B), got ${hash.size} B" }
            out.write(hash)
        }
        return out.toByteArray()
    }

    internal fun u32(v: Int): ByteArray =
        byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    private fun u32Value(value: ByteArray): Int? =
        when (value.size) {
            0 -> null
            1 -> value[0].toInt() and 0xFF
            2 -> ((value[0].toInt() and 0xFF) shl 8) or (value[1].toInt() and 0xFF)
            3 -> ((value[0].toInt() and 0xFF) shl 16) or ((value[1].toInt() and 0xFF) shl 8) or
                (value[2].toInt() and 0xFF)
            else -> ((value[0].toInt() and 0xFF) shl 24) or ((value[1].toInt() and 0xFF) shl 16) or
                ((value[2].toInt() and 0xFF) shl 8) or (value[3].toInt() and 0xFF)
        }

    private fun u64Value(value: ByteArray): Long? {
        if (value.isEmpty()) return null
        var v = 0L
        for (b in value) v = (v shl 8) or (b.toLong() and 0xFF)
        return v
    }
}
