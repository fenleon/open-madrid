package dev.fenn.imessage.codec

import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * The one catchable error for a plist that will not decode, whichever codec threw it.
 * [BplistFormatException] (the binary codec) extends this, so callers that only need
 * "it was not a plist" can catch this type across both encodings. Open so the binary codec
 * can keep its own nested subclass.
 */
open class PlistFormatException(message: String) : IllegalArgumentException(message)

/**
 * A decoded plist date, carried as epoch milliseconds (the exchange format of the XML
 * plist's ISO-8601 `<date>` and of the binary codec's Apple-epoch double).
 */
data class PlistDate(val epochMillis: Long) {
    companion object {
        /** Unix epoch millis of 2001-01-01T00:00:00Z (the Apple epoch). */
        const val APPLE_EPOCH_MILLIS = 978_307_200_000L
    }
}

/**
 * Format dispatch between the two plist encodings per spec §1.2/§4.1: a `bplist00`
 * magic means the binary container, an XML declaration or `<plist>` root means the XML
 * form. Which encoding each IDS endpoint uses is not recorded (TODO(capture) C47), so
 * both codecs stay reachable behind this one entry point.
 */
object Plist {

    private val BINARY_MAGIC = "bplist00".toByteArray(Charsets.US_ASCII)
    private val WHITESPACE = byteArrayOf(' '.code.toByte(), '\t'.code.toByte(), '\n'.code.toByte(), '\r'.code.toByte())

    fun parse(bytes: ByteArray): Any? = when {
        startsWithBinaryMagic(bytes) -> NativePlist.decode(bytes)
        startsWithXml(bytes) -> XmlPlist.decode(bytes)
        else -> throw PlistFormatException(
            "not a plist: neither bplist00 nor an XML plist (starts with ${preview(bytes)})",
        )
    }

    private fun startsWithBinaryMagic(b: ByteArray): Boolean =
        b.size >= BINARY_MAGIC.size && BINARY_MAGIC.indices.all { b[it] == BINARY_MAGIC[it] }

    /** Optional UTF-8 BOM, then optional whitespace, then `<?xml` or `<plist`. */
    private fun startsWithXml(b: ByteArray): Boolean {
        var i = 0
        if (b.size >= 3 && b[0] == 0xEF.toByte() && b[1] == 0xBB.toByte() && b[2] == 0xBF.toByte()) i = 3
        while (i < b.size && WHITESPACE.any { it == b[i] }) i++
        val head = String(b, i, minOf(6, b.size - i), Charsets.US_ASCII)
        return head.startsWith("<?xml") || head.startsWith("<plist")
    }

    private fun preview(b: ByteArray): String {
        if (b.isEmpty()) return "0 bytes"
        val head = b.copyOfRange(0, minOf(8, b.size))
        return head.joinToString(" ") { "0x%02x".format(it) }
    }
}

/** XML-plist date form: ISO-8601 instant (`2024-01-02T03:04:05Z`). */
internal fun PlistDate.toIso8601(): String =
    DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")
        .withZone(ZoneOffset.UTC)
        .format(Instant.ofEpochMilli(epochMillis))
