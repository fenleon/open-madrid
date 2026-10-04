package dev.fenn.imessage.courier

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream

/**
 * The packed courier codec (spec §3.2, C19 closed in rev 26 — the server negotiated ALPN
 * `apns-pack-v1` live and this format flowed): the tag-based alternative to the §3.2 legacy
 * frames. A frame is a 1-byte command, the attribute-block length as a tagged value (width 8),
 * then the attributes. Tagged value: a 1-byte tag whose low `width` bits carry an inline value
 * while they are not all ones; otherwise the all-ones marker followed by a 7-bit continuation
 * varint of the remainder. Attribute: a 1-byte key tag — a single-byte key k (< 0x10) sent as
 * k|flags, longer keys through a rolling key cache (0x20|flags|index reference; 0x10|flags +
 * key-length−1 as a tagged width-4 value, then the key) — then the value: inline integer
 * (|0x80, ≤ 0x1f), wide integer ((byte-length−1)|0xa0, +0x08 negative, big-endian magnitude),
 * data (tagged width 6), string (width 5, |0x40). Cache flags: 0x40 = first occurrence (full
 * value, enters the rolling value cache), 0x80 = reference (tagged width-8 index). Both caches
 * index from the newest entry; the key cache caps at 32 entries, the value cache at ~4 KiB of
 * entries.
 */
class CourierPacked {

    sealed class Value {
        data class Int(val v: Long) : Value()
        class Data(val bytes: ByteArray) : Value()
    }

    class Frame(val command: Int, val fields: List<Field>) {
        data class Field(val id: Int, val value: Value)

        fun intField(id: Int): Long? =
            fields.firstOrNull { it.id == id }?.let { it.value as? Value.Int }?.v

        fun dataField(id: Int): ByteArray? =
            fields.firstOrNull { it.id == id }?.let { it.value as? Value.Data }?.bytes
    }

    class Attr(val id: Int, val value: Value, val valueCached: Boolean = false)

    private val keyTable = ArrayList<ByteArray>()
    private val valueTable = ArrayList<ByteArray>()
    private var valueTableBytes = 0

    // ---- encode ----

    fun encode(command: Int, attrs: List<Attr>): ByteArray {
        val body = ByteArrayOutputStream()
        for (attr in attrs) writeAttr(attr, body)
        val payload = body.toByteArray()
        if (payload.size + 2 > CourierFrame.MAX_FRAME_BYTES) throw IllegalArgumentException("frame too large")
        val out = ByteArrayOutputStream()
        out.write(command)
        writeTagged(out, 8, payload.size.toLong(), 0)
        out.write(payload)
        return out.toByteArray()
    }

    private fun writeAttr(attr: Attr, out: ByteArrayOutputStream) {
        var flags = 0
        var cachedBuf: ByteArray? = null
        var cachedIndex: Int? = null
        if (attr.valueCached) {
            val buf = ByteArrayOutputStream()
            writeValue(attr.value, buf)
            val bytes = buf.toByteArray()
            val existing = indexOf(valueTable, bytes)
            if (existing == null) {
                valueAdd(bytes)
                flags = 0x40
                cachedBuf = bytes
            } else {
                flags = 0x80
                cachedIndex = existing
            }
        }
        val single = attr.id in 0 until 0x10
        if (single) {
            out.write(attr.id or flags)
        } else {
            val existing = indexOf(keyTable, byteArrayOf(attr.id.toByte()))
            if (existing != null) {
                out.write(0x20 or flags or existing)
            } else {
                keyAdd(byteArrayOf(attr.id.toByte()))
                writeTagged(out, 4, 0, 0x10 or flags) // key length − 1: the key is one byte
                out.write(attr.id)
            }
        }
        when {
            cachedIndex != null -> writeTagged(out, 8, cachedIndex.toLong(), 0)
            cachedBuf != null -> out.write(cachedBuf)
            else -> writeValue(attr.value, out)
        }
    }

    private fun writeValue(value: Value, out: ByteArrayOutputStream) {
        when (value) {
            is Value.Data -> {
                writeTagged(out, 6, value.bytes.size.toLong(), 0)
                out.write(value.bytes)
            }
            is Value.Int -> {
                val v = value.v
                if (v in 0..0x1f) {
                    out.write(v.toInt() or 0x80)
                } else {
                    val negative = v < 0
                    val bytes = java.math.BigInteger.valueOf(v).abs().toByteArray()
                    // BigInteger is sign-prefixed two's-complement; the wire carries the magnitude
                    val magnitude = if (bytes[0] == 0.toByte()) bytes.copyOfRange(1, bytes.size) else bytes
                    val tag = (magnitude.size - 1) or 0xa0 or (if (negative) 0x08 else 0)
                    out.write(tag)
                    out.write(magnitude)
                }
            }
        }
    }

    private fun writeTagged(out: ByteArrayOutputStream, width: Int, value: Long, mask: Int) {
        val max = (1L shl width) - 1
        if (value < max) {
            out.write((value.toInt() and 0xff) or mask)
            return
        }
        out.write(max.toInt() or mask)
        var remainder = value - max
        if (remainder == 0L) {
            out.write(0) // the varint form always carries at least one continuation byte
        }
        while (remainder != 0L) {
            var byte = (remainder and 0x7f).toInt()
            remainder = remainder shr 7
            if (remainder != 0L) byte = byte or 0x80
            out.write(byte)
        }
    }

    /** Both caches index 0 = newest entry. */
    private fun indexOf(table: List<ByteArray>, item: ByteArray): Int? {
        for (i in table.indices.reversed()) {
            if (table[i].contentEquals(item)) return table.size - 1 - i
        }
        return null
    }

    private fun keyAdd(item: ByteArray) {
        if (keyTable.size >= 0x20) keyTable.removeAt(0)
        keyTable.add(item)
    }

    private fun valueAdd(item: ByteArray) {
        valueTableBytes += item.size + 0x20
        while (valueTableBytes > 0x1000 && valueTable.isNotEmpty()) {
            val removed = valueTable.removeAt(0)
            valueTableBytes -= removed.size + 0x20
        }
        valueTable.add(item)
    }

    // ---- decode ----

    /** Returns null on clean EOF at a frame boundary; throws on malformed or truncated data. */
    fun decode(input: InputStream): Frame? {
        val command = try {
            input.read()
        } catch (e: EOFException) {
            return null
        }
        if (command == -1) return null
        val lengthTag = try {
            input.read()
        } catch (e: EOFException) {
            return null
        }
        if (lengthTag == -1) return null
        val length = readTagged(input, 8, lengthTag)
        if (length > CourierFrame.MAX_FRAME_BYTES) throw IOException("frame length $length exceeds cap")
        val bytes = readN(input, length.toInt())
        val cursor = ByteArrayInputStream(bytes)
        val fields = ArrayList<Frame.Field>()
        while (cursor.available() > 0) {
            fields.add(readAttr(cursor))
        }
        return Frame(command, fields)
    }

    private fun readAttr(input: InputStream): Frame.Field {
        val tag = readByte(input)
        val id: Int = when {
            tag and 0x20 != 0 -> {
                val idx = tag and 0x1f
                keyTable.getOrNull(keyTable.size - 1 - idx)?.let { it[0].toInt() and 0xff }
                    ?: throw IOException("courier packed: key cache miss for index $idx")
            }
            tag and 0x10 != 0 -> {
                val len = readTagged(input, 4, tag).toInt()
                val key = readN(input, len + 1)
                keyAdd(key)
                key[0].toInt() and 0xff
            }
            else -> tag and 0x0f
        }
        val value: Value = when {
            tag and 0x80 != 0 -> {
                val idx = readTagged(input, 8, readByte(input)).toInt()
                val bytes = valueTable.getOrNull(valueTable.size - 1 - idx)
                    ?: throw IOException("courier packed: value cache miss for index $idx")
                parseValue(ByteArrayInputStream(bytes))
            }
            tag and 0x40 != 0 -> {
                val captured = CapturingStream(input)
                val value = parseValue(captured)
                valueAdd(captured.captured.toByteArray())
                value
            }
            else -> parseValue(input)
        }
        return Frame.Field(id, value)
    }

    private fun parseValue(input: InputStream): Value {
        val tag = readByte(input)
        return when (tag shr 6) {
            0 -> Value.Data(readN(input, readTagged(input, 6, tag).toInt()))
            1 -> Value.Data(readN(input, readTagged(input, 5, tag).toInt())) // string as data
            2 -> if (tag and 0x20 != 0) {
                val length = (tag and 0x07) + 1
                val negative = tag and 0x08 != 0
                val bytes = readN(input, length)
                var v = 0L
                for (b in bytes) v = (v shl 8) or (b.toLong() and 0xff)
                Value.Int(if (negative) -v else v)
            } else {
                Value.Int((tag and 0x1f).toLong())
            }
            else -> if (tag and 0x20 != 0) {
                Value.Int(if (readTagged(input, 4, tag) != 0L) 1 else 0)
            } else {
                throw IOException("courier packed: unsupported value class ${tag shr 6}")
            }
        }
    }

    private fun readTagged(input: InputStream, width: Int, tag: Int): Long {
        val mask = (1 shl width) - 1
        if (tag and mask != mask) return (tag and mask).toLong()
        var number = 0L
        var shift = 0
        while (true) {
            val byte = readByte(input)
            number = number or ((byte and 0x7f).toLong() shl shift)
            if (byte and 0x80 == 0) break
            shift += 7
        }
        return number + mask
    }

    private fun readByte(input: InputStream): Int {
        val b = input.read()
        if (b == -1) throw EOFException("courier packed: truncated frame")
        return b
    }

    private fun readN(input: InputStream, n: Int): ByteArray {
        val out = ByteArray(n)
        var read = 0
        while (read < n) {
            val r = input.read(out, read, n - read)
            if (r == -1) throw EOFException("courier packed: truncated frame")
            read += r
        }
        return out
    }

    private class CapturingStream(val inner: InputStream) : InputStream() {
        val captured = ByteArrayOutputStream()
        override fun read(): Int {
            val b = inner.read()
            if (b != -1) captured.write(b)
            return b
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            val r = inner.read(b, off, len)
            if (r != -1) captured.write(b, off, r)
            return r
        }
    }

    companion object {

        /**
         * The connect frame (§3.3 field ids): state 1, flags, push certificate (12), nonce (13),
         * signature (14), the Rust-only version field 0x10 = 9, and the device token (1) —
         * ABSENT when [token] is null (the first connect of a connection: C19/§3.3, rev 26 —
         * an empty token attribute is the wrong form).
         */
        fun connectFrame(
            token: ByteArray?,
            pushCertificateDer: ByteArray,
            nonce: ByteArray,
            signature: ByteArray,
        ): ByteArray = CourierPacked().encode(
            CourierFrame.CONNECT,
            buildList {
                if (token != null) add(Attr(CourierCommands.CONNECT_FIELD_TOKEN, Value.Data(token), valueCached = true))
                add(Attr(CourierCommands.CONNECT_FIELD_STATE, Value.Int(CourierCommands.CONNECT_STATE.toLong())))
                add(Attr(CourierCommands.CONNECT_FIELD_FLAGS, Value.Int(CourierCommands.CONNECT_FLAGS_BASE.toLong())))
                add(Attr(CourierCommands.CONNECT_FIELD_CERTIFICATE, Value.Data(pushCertificateDer)))
                add(Attr(CourierCommands.CONNECT_FIELD_NONCE, Value.Data(nonce)))
                add(Attr(CourierCommands.CONNECT_FIELD_SIGNATURE, Value.Data(signature)))
                add(Attr(CourierCommands.CONNECT_FIELD_RUST_VERSION, Value.Int(CourierCommands.CONNECT_RUST_VERSION_VALUE.toLong())))
            },
        )

        /** Set state (20): the state byte + the fixed interval constant (§3.3) — sent right after connect. */
        fun setStateFrame(): ByteArray = CourierPacked().encode(
            CourierFrame.SET_STATE,
            listOf(
                Attr(CourierCommands.SET_STATE_FIELD_STATE, Value.Int(CourierCommands.CONNECT_STATE.toLong())),
                Attr(CourierCommands.SET_STATE_FIELD_INTERVAL, Value.Int(CourierCommands.SET_STATE_INTERVAL.toLong())),
            ),
        )

        /**
         * Filter (9): the connect-response token (value-cached) plus the SHA-1 topic hashes as
         * enabled topics (§3.3 field 2, the single-topic-field reading of C57). Sent right after
         * the set state — unfiltered connections are dropped within seconds, which invalidates
         * the connect token before the login can use it (rev 26, live 2026-10-03).
         */
        fun filterFrame(token: ByteArray, enabledTopics: List<String>): ByteArray = CourierPacked().encode(
            CourierFrame.FILTER,
            buildList {
                add(Attr(CourierCommands.CONNECT_FIELD_TOKEN, Value.Data(token), valueCached = true))
                for (topic in enabledTopics) {
                    add(Attr(2, Value.Data(CourierCommands.topicHash(topic)), valueCached = true))
                }
            },
        )

        /** Ping/keepalive (12): no attributes (§3.3). */
        fun ping(): ByteArray = CourierPacked().encode(CourierFrame.KEEPALIVE, emptyList())
    }
}
