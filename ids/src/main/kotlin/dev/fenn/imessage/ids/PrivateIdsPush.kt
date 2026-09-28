package dev.fenn.imessage.ids

import dev.fenn.imessage.courier.CourierCommands
import dev.fenn.imessage.courier.CourierFrame
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * The private-IDS topic of spec §2.3: server-initiated control pushes ride send (10) frames
 * addressed to `com.apple.private.ids` — hashed on the wire (§3.3) — with a small JSON body
 * carrying the command count `c` (c=32 re-register, c=66 handles changed, c=34 devices
 * changed).
 */
object PrivateIdsPush {

    const val TOPIC = "com.apple.private.ids"

    private val topicHash by lazy { CourierCommands.topicHash(TOPIC) }

    /** The send frame that carries a private-IDS push, or null for anything else. */
    fun commandFromFrame(frame: CourierFrame.Frame): Int? {
        if (frame.command != CourierFrame.SEND) return null
        val topic = frame.field(CourierCommands.SEND_FIELD_TOPIC) ?: return null
        if (!topic.contentEquals(topicHash)) return null
        val payload = frame.field(CourierCommands.SEND_FIELD_PAYLOAD) ?: return null
        return parseCommand(payload)
    }

    /** The JSON body's `c` value; a malformed body is dropped, never thrown into the transport. */
    fun parseCommand(body: ByteArray): Int? = runCatching {
        Json.parseToJsonElement(body.decodeToString()).jsonObject["c"]
            ?.jsonPrimitive?.content?.toIntOrNull()
    }.getOrNull()
}
