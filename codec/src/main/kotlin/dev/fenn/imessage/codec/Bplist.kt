package dev.fenn.imessage.codec

/**
 * Binary property list (bplist00) codec per imessage-protocol-spec §4
 * ("Binary plist container format" / "Binary plist object encoding"), which
 * restates Apple's publicly documented Core Foundation binary plist format.
 *
 * Integers: the 1/2/4-byte wire forms are unsigned (zero-extended on decode);
 * the 8-byte form is two's-complement signed, and negative values encode only
 * there — so [BpInt] carries a [Long]. A UID is a 1/2/4/8-byte unsigned
 * integer (marker 0x8n, n = 0..3). Dates are seconds since
 * 2001-01-01T00:00:00Z (the Apple epoch) as a double.
 */
class BplistFormatException(message: String) : PlistFormatException(message)

sealed interface BpValue

data object BpNull : BpValue
data class BpBool(val value: Boolean) : BpValue

/** Signed 64-bit integer. The 1/2/4-byte wire forms are unsigned
 * (zero-extended on decode); negative values ride only the 8-byte
 * two's-complement form, so the representable range is exactly [Long]. */
data class BpInt(val value: Long) : BpValue

data class BpReal(val value: Double) : BpValue

/** Seconds since 2001-01-01T00:00:00Z (Apple epoch). */
data class BpDate(val secondsSince2001: Double) : BpValue

class BpData(val bytes: ByteArray) : BpValue {
    override fun equals(other: Any?) = other is BpData && bytes.contentEquals(other.bytes)
    override fun hashCode() = bytes.contentHashCode()
    override fun toString() = "BpData(${bytes.size} bytes)"
}

data class BpString(val value: String) : BpValue
data class BpArray(val items: List<BpValue>) : BpValue

/** Keys may be any object per spec; protocol plists use string keys. */
class BpDict(val entries: Map<BpValue, BpValue>) : BpValue {
    override fun equals(other: Any?) = other is BpDict && entries == other.entries
    override fun hashCode() = entries.hashCode()
    override fun toString() = "BpDict($entries)"
}

/** 1/2/4/8-byte unsigned integer (marker 0x8n). */
data class BpUid(val value: ULong) : BpValue

object Bplist {

    private val MAGIC = "bplist00".toByteArray(Charsets.US_ASCII)
    private const val TRAILER_SIZE = 32

    fun encode(root: BpValue): ByteArray {
        val objects = ArrayList<BpValue>()
        collect(root, objects)
        val index = java.util.IdentityHashMap<BpValue, Int>(objects.size * 2)
        objects.forEachIndexed { i, v -> index[v] = i }
        val count = objects.size

        val refWidth = widthFor(count)
        val payloads = objects.map { encodeObject(it, index, refWidth) }

        var offsetTableOffset = MAGIC.size
        val offsets = IntArray(count)
        for (i in 0 until count) {
            offsets[i] = offsetTableOffset
            offsetTableOffset += payloads[i].size
        }

        val offWidth = widthFor(offsetTableOffset)
        val out = ByteArray(offsetTableOffset + count * offWidth + TRAILER_SIZE)
        MAGIC.copyInto(out, 0)
        var pos = MAGIC.size
        for (p in payloads) {
            p.copyInto(out, pos)
            pos += p.size
        }
        for (o in offsets) {
            writeBE(out, pos, offWidth, o.toLong())
            pos += offWidth
        }
        // Trailer: 5 unused, 1 sort version, 1 offset width, 1 ref width,
        // then 8-byte big-endian count / top index / offset-table offset.
        out[pos + 6] = offWidth.toByte()
        out[pos + 7] = refWidth.toByte()
        writeBE(out, pos + 8, 8, count.toLong())
        writeBE(out, pos + 16, 8, 0L) // top object is always index 0 here
        writeBE(out, pos + 24, 8, offsetTableOffset.toLong())
        return out
    }

    private fun collect(v: BpValue, out: MutableList<BpValue>) {
        out.add(v)
        when (v) {
            is BpArray -> v.items.forEach { collect(it, out) }
            is BpDict -> {
                v.entries.keys.forEach { collect(it, out) }
                v.entries.values.forEach { collect(it, out) }
            }
            else -> {}
        }
    }

    /** Minimal 1/2/4/8-byte width whose unsigned range holds [value]. */
    private fun widthFor(value: Int): Int {
        var w = 1
        while (value > (1L shl (8 * w)) - 1) w *= 2
        return w
    }

    private fun writeBE(out: ByteArray, pos: Int, width: Int, value: Long) {
        for (i in 0 until width) {
            out[pos + i] = (value ushr (8 * (width - 1 - i))).toByte()
        }
    }

    private fun nibbleFor(width: Int) = when (width) {
        1 -> 0; 2 -> 1; 4 -> 2; else -> 3
    }

    private fun inlineIntBytes(value: Int): ByteArray {
        val w = widthFor(value)
        val b = ByteArray(1 + w)
        b[0] = (0x10 or nibbleFor(w)).toByte()
        writeBE(b, 1, w, value.toLong())
        return b
    }

    /** Low nibble < 15 carries the count; else 0xF + inline 0x1n integer. */
    private fun writeCount(count: Int, markerHigh: Int): ByteArray {
        return if (count < 15) {
            byteArrayOf(((markerHigh shl 4) or count).toByte())
        } else {
            byteArrayOf(((markerHigh shl 4) or 0x0F).toByte()) + inlineIntBytes(count)
        }
    }

    private fun encodeObject(v: BpValue, index: MutableMap<BpValue, Int>, refWidth: Int): ByteArray {
        return when (v) {
            is BpNull -> byteArrayOf(0x00)
            is BpBool -> byteArrayOf(if (v.value) 0x09 else 0x08)
            is BpInt -> {
                val w = if (v.value < 0) 8 else intWidth(v.value)
                val b = ByteArray(1 + w)
                b[0] = (0x10 or nibbleFor(w)).toByte()
                for (i in 0 until w) {
                    b[1 + i] = (v.value shr (8 * (w - 1 - i))).toByte()
                }
                b
            }
            is BpReal -> {
                val b = ByteArray(9)
                b[0] = 0x23
                putDouble(b, 1, v.value)
                b
            }
            is BpDate -> {
                val b = ByteArray(9)
                b[0] = 0x33
                putDouble(b, 1, v.secondsSince2001)
                b
            }
            is BpData -> writeCount(v.bytes.size, 0x4) + v.bytes
            is BpString -> {
                if (v.value.all { it.code < 0x80 }) {
                    val ascii = v.value.toByteArray(Charsets.US_ASCII)
                    writeCount(ascii.size, 0x5) + ascii
                } else {
                    val utf16 = v.value.toByteArray(Charsets.UTF_16BE)
                    writeCount(utf16.size / 2, 0x6) + utf16 // length in code units, not bytes
                }
            }
            is BpUid -> {
                val w = ulongWidth(v.value)
                if (w > 8) throw BplistFormatException("UID too large: $v")
                val b = ByteArray(1 + w)
                b[0] = (0x80 or nibbleFor(w)).toByte()
                for (i in 0 until w) {
                    b[1 + i] = (v.value shr (8 * (w - 1 - i))).toByte()
                }
                b
            }
            is BpArray -> {
                val head = writeCount(v.items.size, 0xA)
                val refs = ByteArray(v.items.size * refWidth)
                var pos = 0
                for (item in v.items) {
                    writeBE(refs, pos, refWidth, index[item]!!.toLong())
                    pos += refWidth
                }
                head + refs
            }
            is BpDict -> {
                val head = writeCount(v.entries.size, 0xD)
                val refs = ByteArray(v.entries.size * 2 * refWidth)
                var pos = 0
                for (k in v.entries.keys) {
                    writeBE(refs, pos, refWidth, index[k]!!.toLong())
                    pos += refWidth
                }
                for ((_, value) in v.entries) {
                    writeBE(refs, pos, refWidth, index[value]!!.toLong())
                    pos += refWidth
                }
                head + refs
            }
        }
    }

    private fun ulongWidth(value: ULong): Int {
        var w = 1
        while (w < 8 && value > ((1UL shl (8 * w)) - 1UL)) w *= 2
        return w
    }

    /** Minimal 1/2/4/8-byte width for a non-negative integer. */
    private fun intWidth(value: Long): Int {
        var w = 1
        while (w < 8 && value > ((1L shl (8 * w)) - 1)) w *= 2
        return w
    }

    private fun putDouble(b: ByteArray, pos: Int, v: Double) {
        val bits = java.lang.Double.doubleToLongBits(v)
        for (i in 0 until 8) {
            b[pos + i] = (bits ushr (8 * (7 - i))).toByte()
        }
    }

    fun decode(bytes: ByteArray): BpValue {
        if (bytes.size < MAGIC.size + TRAILER_SIZE) {
            throw BplistFormatException("input too short (${bytes.size} bytes)")
        }
        for (i in MAGIC.indices) {
            if (bytes[i] != MAGIC[i]) throw BplistFormatException("bad magic — not bplist00")
        }
        val base = bytes.size - TRAILER_SIZE
        val offWidth = bytes[base + 6].toInt() and 0xFF
        val refWidth = bytes[base + 7].toInt() and 0xFF
        if (offWidth !in intArrayOf(1, 2, 4, 8) || refWidth !in intArrayOf(1, 2, 4, 8)) {
            throw BplistFormatException("invalid offset/ref width ($offWidth/$refWidth)")
        }
        val count = readU64(bytes, base + 8)
        val top = readU64(bytes, base + 16)
        val tableOffset = readU64(bytes, base + 24)
        if (count == 0L || top >= count) {
            throw BplistFormatException("top object index $top out of range ($count objects)")
        }
        if (tableOffset > base.toLong() || count > (base - tableOffset) / offWidth) {
            throw BplistFormatException("offset table overruns the file")
        }
        val offsets = LongArray(count.toInt())
        var pos = tableOffset
        for (i in offsets.indices) {
            offsets[i] = readUnsigned(bytes, pos.toInt(), offWidth)
            pos += offWidth
        }
        return Decoder(bytes, offsets, tableOffset, refWidth).parseAt(top.toInt())
    }

    private class Decoder(
        val bytes: ByteArray,
        val offsets: LongArray,
        val tableOffset: Long,
        val refWidth: Int,
    ) {
        private val memo = HashMap<Int, BpValue>()

        fun parseAt(index: Int): BpValue {
            memo[index]?.let { return it }
            if (index < 0 || index >= offsets.size) {
                throw BplistFormatException("object reference $index out of range (${offsets.size} objects)")
            }
            val offset = offsets[index]
            if (offset >= tableOffset) {
                throw BplistFormatException("object $index offset $offset outside the object area")
            }
            val v = parseMarker(offset.toInt())
            memo[index] = v
            return v
        }

        private fun parseMarker(pos: Int): BpValue {
            if (pos < 0 || pos >= tableOffset) throw BplistFormatException("truncated object at $pos")
            val marker = bytes[pos].toInt() and 0xFF
            val high = marker ushr 4
            val low = marker and 0x0F
            return when (high) {
                0x0 -> when (marker) {
                    0x00 -> BpNull
                    0x08 -> BpBool(false)
                    0x09 -> BpBool(true)
                    else -> throw BplistFormatException("unknown simple value marker 0x%02X".format(marker))
                }
                0x1 -> {
                    if (low > 3) throw BplistFormatException("invalid integer width 2^$low")
                    val w = 1 shl low
                    // 1/2/4-byte forms are unsigned (zero-extended); the
                    // 8-byte form is two's-complement signed.
                    BpInt(if (w == 8) readLongBE(pos + 1) else readUnsigned(pos + 1, w))
                }
                0x2 -> when (low) {
                    2 -> BpReal(
                        java.lang.Float.intBitsToFloat(readUnsigned(pos + 1, 4).toInt()).toDouble()
                    )
                    3 -> BpReal(readDouble(pos + 1))
                    else -> throw BplistFormatException("invalid real width 2^$low")
                }
                0x3 -> {
                    if (marker != 0x33) throw BplistFormatException("unknown marker 0x%02X".format(marker))
                    BpDate(readDouble(pos + 1))
                }
                0x4 -> {
                    val (len, body) = readCount(pos, low)
                    BpData(readBytes(body, len))
                }
                0x5 -> {
                    val (len, body) = readCount(pos, low)
                    val b = readBytes(body, len)
                    if (b.any { it.toInt() and 0x80 != 0 }) {
                        throw BplistFormatException("non-ASCII byte in 0x5 string")
                    }
                    BpString(String(b, Charsets.US_ASCII))
                }
                0x6 -> {
                    val (units, body) = readCount(pos, low) // length in code units, not bytes
                    BpString(String(readBytes(body, units * 2), Charsets.UTF_16BE))
                }
                0x8 -> {
                    if (low > 3) throw BplistFormatException("invalid UID width 2^$low")
                    BpUid(readUnsignedLong(pos + 1, 1 shl low))
                }
                0xA -> {
                    val (n, body) = readCount(pos, low)
                    val items = ArrayList<BpValue>(n)
                    var p = body
                    repeat(n) {
                        items.add(parseRef(p))
                        p += refWidth
                    }
                    BpArray(items)
                }
                0xD -> {
                    val (n, body) = readCount(pos, low)
                    var p = body
                    val keys = ArrayList<BpValue>(n)
                    repeat(n) {
                        keys.add(parseRef(p))
                        p += refWidth
                    }
                    val values = ArrayList<BpValue>(n)
                    repeat(n) {
                        values.add(parseRef(p))
                        p += refWidth
                    }
                    BpDict(keys.zip(values).toMap(LinkedHashMap()))
                }
                else -> throw BplistFormatException("unknown marker 0x%02X".format(marker))
            }
        }

        /** Returns (count, body start). Count < 15 rides the low nibble; 15+ is an inline 0x1n integer. */
        private fun readCount(pos: Int, low: Int): Pair<Int, Int> {
            return if (low < 15) {
                low to pos + 1
            } else {
                val m = bytes.getOrNull(pos + 1)?.toInt()?.and(0xFF)
                    ?: throw BplistFormatException("truncated inline count at $pos")
                if (m ushr 4 != 0x1) throw BplistFormatException("inline count is not an integer marker")
                val n = m and 0x0F
                if (n > 3) throw BplistFormatException("invalid inline integer width 2^$n")
                val w = 1 shl n
                readUnsigned(pos + 2, w).toInt() to pos + 2 + w
            }
        }

        private fun parseRef(pos: Int): BpValue = parseAt(readUnsigned(pos, refWidth).toInt())

        private fun readBytes(pos: Int, len: Int): ByteArray {
            if (pos < 0 || len < 0 || pos.toLong() + len > tableOffset) {
                throw BplistFormatException("read of $len bytes at $pos overruns the object area")
            }
            return bytes.copyOfRange(pos, pos + len)
        }

        private fun readUnsignedLong(pos: Int, width: Int): ULong {
            if (pos < 0 || pos + width > bytes.size) {
                throw BplistFormatException("read of $width bytes at $pos overruns the file")
            }
            var v = 0UL
            for (i in 0 until width) {
                v = (v shl 8) or (bytes[pos + i].toULong() and 0xFFUL)
            }
            return v
        }

        private fun readUnsigned(pos: Int, width: Int) = readUnsignedLong(pos, width).toLong()

        private fun readLongBE(pos: Int): Long {
            var v = 0L
            for (i in 0 until 8) {
                v = (v shl 8) or (bytes[pos + i].toLong() and 0xFF)
            }
            return v
        }

        private fun readDouble(pos: Int): Double {
            var bits = 0L
            for (i in 0 until 8) {
                bits = (bits shl 8) or (bytes[pos + i].toLong() and 0xFF)
            }
            return java.lang.Double.longBitsToDouble(bits)
        }
    }

    private fun readU64(bytes: ByteArray, pos: Int): Long {
        var v = 0L
        for (i in 0 until 8) {
            v = (v shl 8) or (bytes[pos + i].toLong() and 0xFF)
        }
        return v
    }

    private fun readUnsigned(bytes: ByteArray, pos: Int, width: Int): Long {
        var v = 0L
        for (i in 0 until width) {
            v = (v shl 8) or (bytes[pos + i].toLong() and 0xFF)
        }
        return v
    }
}
