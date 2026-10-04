package dev.fenn.imessage.courier

import java.io.ByteArrayInputStream
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The packed courier codec (§3.2, C19): encode/decode round trips over the tagged-value forms
 * (inline and wide integers, data, the width-escape varint), the rolling key/value caches, and
 * the frame builders' §3.3 field ids.
 */
class CourierPackedTest {

    private fun decoded(bytes: ByteArray): CourierPacked.Frame {
        val frame = CourierPacked().decode(ByteArrayInputStream(bytes))
        assertTrue(frame != null, "frame decoded")
        return frame
    }

    @Test
    fun dataValuesRoundTrip() {
        val bytes = CourierPacked().encode(
            7,
            listOf(
                CourierPacked.Attr(1, CourierPacked.Value.Data(byteArrayOf(1, 2, 3))),
                CourierPacked.Attr(0x12, CourierPacked.Value.Data(ByteArray(100) { it.toByte() })),
            ),
        )
        val frame = decoded(bytes)
        assertEquals(7, frame.command)
        assertContentEquals(byteArrayOf(1, 2, 3), frame.dataField(1))
        val wide = frame.dataField(0x12)!!
        assertEquals(100, wide.size)
        assertEquals(99, wide[99].toInt())
    }

    @Test
    fun integerEncodingsRoundTrip() {
        val bytes = CourierPacked().encode(
            7,
            listOf(
                CourierPacked.Attr(1, CourierPacked.Value.Int(5)), // inline (≤ 0x1f)
                CourierPacked.Attr(2, CourierPacked.Value.Int(0x20)), // wide single byte
                CourierPacked.Attr(3, CourierPacked.Value.Int(0x010203040506)), // wide multi-byte
                CourierPacked.Attr(4, CourierPacked.Value.Int(-3)), // negative (0x08 bit)
                CourierPacked.Attr(5, CourierPacked.Value.Int(CourierCommands.SET_STATE_INTERVAL.toLong())),
            ),
        )
        val frame = decoded(bytes)
        assertEquals(5L, frame.intField(1))
        assertEquals(0x20L, frame.intField(2))
        assertEquals(0x010203040506L, frame.intField(3))
        assertEquals(-3L, frame.intField(4))
        assertEquals(CourierCommands.SET_STATE_INTERVAL.toLong(), frame.intField(5))
    }

    @Test
    fun valueCacheReferenceDecodesToTheFirstValue() {
        val encoder = CourierPacked()
        val token = ByteArray(32) { (it + 1).toByte() }
        val bytes = encoder.encode(
            7,
            listOf(
                CourierPacked.Attr(1, CourierPacked.Value.Data(token), valueCached = true),
                CourierPacked.Attr(2, CourierPacked.Value.Data(token), valueCached = true),
            ),
        )
        val frame = decoded(bytes)
        assertContentEquals(token, frame.dataField(1))
        assertContentEquals(token, frame.dataField(2))
    }

    @Test
    fun keyCacheReferenceDecodesToTheSameId() {
        val encoder = CourierPacked()
        val bytes = encoder.encode(
            7,
            listOf(
                CourierPacked.Attr(0x20, CourierPacked.Value.Int(1)),
                CourierPacked.Attr(0x20, CourierPacked.Value.Int(2)),
            ),
        )
        val frame = decoded(bytes)
        val values = frame.fields.filter { it.id == 0x20 }.map { (it.value as CourierPacked.Value.Int).v }
        assertEquals(listOf(1L, 2L), values)
    }

    @Test
    fun cleanEofAtFrameBoundaryReturnsNull() {
        assertNull(CourierPacked().decode(ByteArrayInputStream(ByteArray(0))))
    }

    @Test
    fun connectFrameCarriesTheRecordedFieldsWithoutTheToken() {
        val cert = ByteArray(16) { 1 }
        val nonce = ByteArray(17) { 2 }
        val signature = ByteArray(8) { 3 }
        val frame = decoded(CourierPacked.connectFrame(null, cert, nonce, signature))
        assertEquals(CourierFrame.CONNECT, frame.command)
        assertEquals(CourierCommands.CONNECT_STATE.toLong(), frame.intField(CourierCommands.CONNECT_FIELD_STATE))
        assertEquals(
            CourierCommands.CONNECT_FLAGS_BASE.toLong(),
            frame.intField(CourierCommands.CONNECT_FIELD_FLAGS),
        )
        assertContentEquals(cert, frame.dataField(CourierCommands.CONNECT_FIELD_CERTIFICATE))
        assertContentEquals(nonce, frame.dataField(CourierCommands.CONNECT_FIELD_NONCE))
        assertContentEquals(signature, frame.dataField(CourierCommands.CONNECT_FIELD_SIGNATURE))
        assertEquals(
            CourierCommands.CONNECT_RUST_VERSION_VALUE.toLong(),
            frame.intField(CourierCommands.CONNECT_FIELD_RUST_VERSION),
        )
        // First connect: the token attribute is ABSENT, not empty (C19, rev 26).
        assertEquals(null, frame.dataField(CourierCommands.CONNECT_FIELD_TOKEN))
    }

    @Test
    fun connectFrameCarriesTheTokenWhenPresent() {
        val token = ByteArray(32) { 4 }
        val frame = decoded(CourierPacked.connectFrame(token, ByteArray(0), ByteArray(0), ByteArray(0)))
        assertContentEquals(token, frame.dataField(CourierCommands.CONNECT_FIELD_TOKEN))
    }

    @Test
    fun setStateFrameCarriesStateAndInterval() {
        val frame = decoded(CourierPacked.setStateFrame())
        assertEquals(CourierFrame.SET_STATE, frame.command)
        assertEquals(1L, frame.intField(CourierCommands.SET_STATE_FIELD_STATE))
        assertEquals(CourierCommands.SET_STATE_INTERVAL.toLong(), frame.intField(CourierCommands.SET_STATE_FIELD_INTERVAL))
    }

    @Test
    fun filterFrameCarriesTokenAndSha1TopicHashes() {
        val token = ByteArray(32) { 5 }
        val frame = decoded(CourierPacked.filterFrame(token, listOf("com.apple.madrid", "com.apple.private.alloy.sms")))
        assertEquals(CourierFrame.FILTER, frame.command)
        assertContentEquals(token, frame.dataField(1))
        val topicHashes = frame.fields.filter { it.id == 2 }.map { (it.value as CourierPacked.Value.Data).bytes }
        assertEquals(2, topicHashes.size)
        assertContentEquals(sha1("com.apple.madrid"), topicHashes[0])
        assertContentEquals(sha1("com.apple.private.alloy.sms"), topicHashes[1])
    }

    @Test
    fun pingCarriesNoAttributes() {
        val frame = decoded(CourierPacked.ping())
        assertEquals(CourierFrame.KEEPALIVE, frame.command)
        assertEquals(0, frame.fields.size)
    }

    private fun sha1(text: String): ByteArray =
        MessageDigest.getInstance("SHA-1").digest(text.toByteArray(Charsets.UTF_8))
}
