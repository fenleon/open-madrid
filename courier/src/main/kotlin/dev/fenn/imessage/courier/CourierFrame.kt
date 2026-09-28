package dev.fenn.imessage.courier

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream

/**
 * APNs courier legacy frame codec per spec §3.2: 1-byte command, 4-byte big-endian total
 * length covering the whole field block after the command byte, then fields (1-byte id,
 * 2-byte big-endian length, value). Command numbers and the per-command field-id tables are
 * wire facts (spec §3.3, C45 closed in rev 12) — builders live in [CourierCommands] /
 * [CourierConnect]. Payload command 160 is a `c` value inside command-10 plists, not a frame
 * command (the payload layer owns it; nothing here builds it).
 */
object CourierFrame {

    // Command numbers (spec §3.3)
    const val CONNECT = 7
    const val CONNECT_RESPONSE = 8
    const val FILTER = 9
    const val SEND = 10
    const val SEND_ACK = 11
    const val KEEPALIVE = 12
    const val KEEPALIVE_ACK = 13
    const val SET_STATE = 20

    /**
     * Tunnel request/response (spec §2.1): IDS lookups ride the APNs tunnel — 96 carries the
     * URL, headers, content type, body and a 16-byte request UUID; the 97 reply carries the
     * same UUID, a status field and the body, on the same topic. Field-id tables live in
     * [CourierCommands.TunnelFieldIds] (the spec records the field set, not the ids).
     */
    const val TUNNEL_REQUEST = 96
    const val TUNNEL_RESPONSE = 97

    /** Sanity cap on frame size — the spec's advertised message sizes are 4–15 KiB (§3.3). */
    const val MAX_FRAME_BYTES = 256 * 1024

    class Frame(val command: Int, val fields: List<Field>) {
        data class Field(val id: Int, val value: ByteArray)

        fun field(id: Int): ByteArray? = fields.firstOrNull { it.id == id }?.value

        override fun equals(other: Any?): Boolean =
            other is Frame && other.command == command && other.fields.size == fields.size &&
                other.fields.zip(fields).all { (a, b) -> a.id == b.id && a.value.contentEquals(b.value) }

        override fun hashCode(): Int = command * 31 + fields.size
    }

    fun encode(command: Int, fields: List<Pair<Int, ByteArray>> = emptyList()): ByteArray {
        val body = ByteArrayOutputStream()
        for ((id, value) in fields) {
            if (value.size > 0xFFFF) throw IllegalArgumentException("field $id too large (${value.size} B)")
            body.write(id)
            body.write((value.size shr 8) and 0xFF)
            body.write(value.size and 0xFF)
            body.write(value)
        }
        val payload = body.toByteArray()
        if (5 + payload.size > MAX_FRAME_BYTES) throw IllegalArgumentException("frame too large")
        val out = ByteArrayOutputStream(5 + payload.size)
        out.write(command)
        writeU32(out, payload.size)
        out.write(payload)
        return out.toByteArray()
    }

    /** Returns null on clean EOF (peer closed between frames); throws on malformed data. */
    fun decode(input: InputStream): Frame? {
        val data = DataInputStream(input)
        val command = try {
            data.readUnsignedByte()
        } catch (e: EOFException) {
            return null
        }
        val length = readU32(data)
        if (length > MAX_FRAME_BYTES) throw IOException("frame length $length exceeds cap")
        var remaining = length
        val fields = ArrayList<Frame.Field>()
        while (remaining > 0) {
            if (remaining < 3) throw IOException("truncated field header")
            val id = data.readUnsignedByte()
            val valueLen = data.readUnsignedShort()
            if (valueLen + 3 > remaining) throw IOException("field overruns frame")
            val value = ByteArray(valueLen)
            data.readFully(value)
            fields.add(Frame.Field(id, value))
            remaining -= 3 + valueLen
        }
        return Frame(command, fields)
    }

    private fun writeU32(out: ByteArrayOutputStream, v: Int) {
        out.write((v ushr 24) and 0xFF)
        out.write((v ushr 16) and 0xFF)
        out.write((v ushr 8) and 0xFF)
        out.write(v and 0xFF)
    }

    private fun readU32(data: DataInputStream): Int {
        val b = ByteArray(4)
        data.readFully(b)
        return ((b[0].toInt() and 0xFF) shl 24) or ((b[1].toInt() and 0xFF) shl 16) or
            ((b[2].toInt() and 0xFF) shl 8) or (b[3].toInt() and 0xFF)
    }
}
