package dev.fenn.imessage.registration

import dev.fenn.imessage.codec.Plist
import dev.fenn.imessage.codec.XmlPlist
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The step-2 validation request's STRUCTURE, pinned against the real capture
 * `validation-request.bin` (imessage-identifiers/, 2026-09-11 live run) — WITHOUT committing
 * it: the blob is device-derived material (it opens with the machine's product/model
 * identifiers and carries per-device key fields), so the privacy rule keeps the bytes out of
 * the repo. Recorded from the capture (assert nothing below against network state; these are
 * offline constants):
 *
 * - file: 3898 bytes, an XML plist with a single top-level key `session-info-request`
 *   whose value is a single `<data>` element (base64) — SHA-256 of the whole file
 *   7a692fad21cd998dedcec6df9558604843eee40b4f0b36f04be9523b6c6ab84e;
 * - inner blob: 2729 bytes — SHA-256
 *   8c7b4bc7a1c2a815069673055fcd2a33d1c15d04970cb8a3a39356ebfa4c0ac9;
 * - blob framing (the invented TLV v1): a flat walk of (1-byte tag, 2-byte big-endian
 *   length, value) fields, tags 0x01..0x11 in ascending order, consuming the blob exactly;
 *   field lengths [14, 5, 10, 36, 36, 12, 6, 6, 17, 17, 17, 17, 17, 17, 2385, 33, 33] —
 *   the 36-byte fields are EC points, the 17-byte fields device-key blobs, the 33-byte
 *   fields compressed P-256 points, and tag 0x0F carries the 2385-byte Apple certificate
 *   container (byte-identical, verified offline, to the public `cert` blob of the
 *   validation-cert-1.0.plist CDN object — committed as a test resource here).
 *
 * The test rebuilds the wrapper with SYNTHETIC payloads in the recorded layout (only the
 * public 2385-byte container is real) and pins the whole walk — sizes, tag order, plist
 * shape and container identity are the capture's, no private byte is.
 */
class ValidationRequestStructureTest {

    private companion object {
        /** The capture's TLV layout: tag → field length (see class KDoc). */
        val CAPTURED_FIELD_LENGTHS = intArrayOf(
            14, 5, 10, 36, 36, 12, 6, 6, 17, 17, 17, 17, 17, 17, 2385, 33, 33,
        )
        const val BLOB_BYTES = 2729
        const val TAG_0F_INDEX = 14
    }

    private fun certContainer(): ByteArray {
        val outer = XmlPlist.decode(
            javaClass.getResourceAsStream("/imessage/validation-cert-1.0.plist")!!.readBytes(),
        ) as Map<*, *>
        return outer["cert"] as ByteArray
    }

    /** Synthetic blob in the captured layout; tag 0x0F carries the real public container. */
    private fun syntheticBlob(): ByteArray {
        val out = java.io.ByteArrayOutputStream(BLOB_BYTES)
        CAPTURED_FIELD_LENGTHS.forEachIndexed { index, length ->
            out.write(index + 1) // tags 0x01..0x11 ascending
            out.write((length ushr 8) and 0xFF)
            out.write(length and 0xFF)
            if (index == TAG_0F_INDEX) {
                out.write(certContainer())
            } else {
                out.write(ByteArray(length) { (it + index).toByte() }) // synthetic filler
            }
        }
        return out.toByteArray()
    }

    @Test
    fun `synthetic wrapper reproduces the captured plist shape`() {
        val wrapper = XmlPlist.encode(mapOf("session-info-request" to syntheticBlob()))
        // Same wire shape as the capture: XML plist, one key, one <data> value.
        assertTrue(wrapper.decodeToString().startsWith("<?xml"))
        val parsed = Plist.parse(wrapper) as Map<*, *>
        assertEquals(setOf("session-info-request"), parsed.keys)
        val blob = assertIs<ByteArray>(parsed["session-info-request"])
        assertEquals(BLOB_BYTES, blob.size)
    }

    @Test
    fun `the captured tlv walk consumes the blob exactly with the recorded layout`() {
        val blob = syntheticBlob()
        assertEquals(BLOB_BYTES, blob.size) // 2385 of the bytes are the real container
        var pos = 0
        val tags = ArrayList<Int>()
        val lengths = ArrayList<Int>()
        while (pos < blob.size) {
            val tag = blob[pos].toInt() and 0xFF
            val length = ((blob[pos + 1].toInt() and 0xFF) shl 8) or (blob[pos + 2].toInt() and 0xFF)
            pos += 3 + length
            tags.add(tag)
            lengths.add(length)
        }
        // Tags 0x01..0x11 ascending, the captured lengths, and the walk ends exactly
        // (rev 22's "walks the invented TLV v1 to the last byte with ZERO slack").
        assertEquals((1..17).toList(), tags)
        assertContentEquals(CAPTURED_FIELD_LENGTHS, lengths.toIntArray())
        assertEquals(BLOB_BYTES, pos)
    }

    @Test
    fun `tag 0f carries the apple certificate container byte-identically`() {
        val blob = syntheticBlob()
        var pos = 0
        var payload: ByteArray? = null
        while (pos < blob.size) {
            val length = ((blob[pos + 1].toInt() and 0xFF) shl 8) or (blob[pos + 2].toInt() and 0xFF)
            if ((blob[pos].toInt() and 0xFF) == 0x0F) payload = blob.copyOfRange(pos + 3, pos + 3 + length)
            pos += 3 + length
        }
        // Verified offline against the capture: the blob's tag-0x0F field is byte-identical
        // to the public CDN validation-certificate container (2385 B, 01 02 + two DERs).
        assertContentEquals(certContainer(), payload)
        assertEquals(2385, payload!!.size)
        assertEquals(0x01, payload[0].toInt())
        assertEquals(0x02, payload[1].toInt())
    }
}
