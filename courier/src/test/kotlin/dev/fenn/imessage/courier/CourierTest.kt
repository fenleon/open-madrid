package dev.fenn.imessage.courier

import java.io.ByteArrayInputStream
import java.io.IOException
import java.security.KeyPairGenerator
import java.security.Signature
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CourierFrameTest {

    private fun roundTrip(frame: CourierFrame.Frame): CourierFrame.Frame {
        val bytes = CourierFrame.encode(frame.command, frame.fields.map { it.id to it.value })
        return CourierFrame.decode(ByteArrayInputStream(bytes))!!
    }

    // Hand-computed: keepalive (12) has no fields (spec §3.3) → 0C 00000000
    @Test
    fun knownAnswerEmptyFrame() {
        assertContentEquals(byteArrayOf(0x0C, 0, 0, 0, 0), CourierFrame.encode(CourierFrame.KEEPALIVE))
    }

    @Test
    fun knownAnswerSingleField() {
        val f = byteArrayOf(0x10, 0, 1, 9)
        val expected = byteArrayOf(20, 0, 0, 0, 4) + f
        assertContentEquals(expected, CourierFrame.encode(20, listOf(0x10 to byteArrayOf(9))))
        assertEquals(CourierFrame.decode(ByteArrayInputStream(expected))!!.field(0x10)!!.single().toInt(), 9)
    }

    @Test
    fun roundTripMultiField() {
        val frame = CourierFrame.Frame(
            CourierFrame.SEND,
            listOf(
                CourierFrame.Frame.Field(1, ByteArray(300) { it.toByte() }), // 2-byte field length path
                CourierFrame.Frame.Field(2, byteArrayOf(1)),
                CourierFrame.Frame.Field(3, ByteArray(0)),
            ),
        )
        assertEquals(frame, roundTrip(frame))
        assertEquals(300, frame.fields[0].value.size)
    }

    @Test
    fun backToBackFramesDecode() {
        val a = CourierFrame.encode(CourierFrame.KEEPALIVE)
        val b = CourierFrame.encode(CourierFrame.SEND_ACK, listOf(1 to byteArrayOf(5, 6)))
        val input = ByteArrayInputStream(a + b)
        assertEquals(CourierFrame.KEEPALIVE, CourierFrame.decode(input)!!.command)
        val ack = CourierFrame.decode(input)!!
        assertEquals(CourierFrame.SEND_ACK, ack.command)
        assertContentEquals(byteArrayOf(5, 6), ack.field(1))
        assertNull(CourierFrame.decode(input)) // EOF between frames is a clean null
    }

    @Test
    fun decodeRejectsMalformed() {
        // length prefix beyond the cap
        assertFailsWith<IOException> {
            CourierFrame.decode(ByteArrayInputStream(byteArrayOf(12, 0x10, 0, 0, 0)))
        }
        // field overruns the frame: length=6 but field claims 3+5
        assertFailsWith<IOException> {
            CourierFrame.decode(ByteArrayInputStream(byteArrayOf(12, 0, 0, 0, 6, 1, 0, 5, 9, 9)))
        }
        // truncated stream mid-frame
        assertFailsWith<IOException> {
            CourierFrame.decode(ByteArrayInputStream(byteArrayOf(12, 0, 0)))
        }
    }
}

class CourierClientHelpersTest {

    // No TLS in helper tests — the pinned-root factory is caller-supplied (port note).
    private fun stubClient() =
        CourierClient(CourierClient.Config("courier.push.apple.com")) { _, _ ->
            error("no TLS in helper tests")
        }

    @Test
    fun courierHostIsShardPrefixed() {
        val random = java.security.SecureRandom()
        repeat(50) {
            val host = CourierClient.courierHost("courier.push.apple.com", 50, random)
            val shard = host.substringBefore('-').toInt()
            assertTrue(shard in 1..50, "shard out of range: $host")
            assertTrue(host.endsWith("-courier.push.apple.com"))
        }
    }

    @Test
    fun backoffGrowsAndCaps() {
        assertEquals(1000, CourierClient.backoffDelayMs(0, 30_000))
        assertEquals(2000, CourierClient.backoffDelayMs(1, 30_000))
        assertEquals(8000, CourierClient.backoffDelayMs(3, 30_000))
        assertEquals(30_000, CourierClient.backoffDelayMs(10, 30_000))
        assertEquals(30_000, CourierClient.backoffDelayMs(100, 30_000))
    }

    @Test
    fun messageIdInRange() {
        val client = stubClient()
        repeat(100) {
            val id = client.newMessageId()
            assertTrue(id in 1..(Int.MAX_VALUE - 1), "message id out of range: $id")
        }
    }
}

/** The §3.3 field-id tables (C45, closed in rev 12) — known-answer where bytes are recorded. */
class CourierCommandsTest {

    private val token = ByteArray(32) { (0x10 + it).toByte() }
    private val cert = ByteArray(24) { (0x20 + it).toByte() }
    private val nonce = ByteArray(17) { (0x30 + it).toByte() }
    private val signature = ByteArray(8) { (0x40 + it).toByte() }

    @Test
    fun connectFrameFieldsInRecordedOrder() {
        val frame = CourierConnect.connectFrame(token, cert, nonce, signature)
        assertEquals(CourierFrame.CONNECT, frame.command)
        // token/state/flags/cert/nonce/signature, ids 1/2/5/12/13/14 (spec §3.3)
        assertContentEquals(listOf(1, 2, 5, 12, 13, 14), frame.fields.map { it.id })
        assertContentEquals(token, frame.field(1))
        assertEquals(1, frame.field(2)!![0].toInt()) // the state byte (1)
        assertEquals(0x41, frame.field(5)!![0].toInt()) // base flags 0b1000001
        assertContentEquals(cert, frame.field(12))
        assertContentEquals(nonce, frame.field(13))
        assertContentEquals(signature, frame.field(14))
    }

    @Test
    fun connectFrameKnownAnswerBytes() {
        // Whole-frame layout for a 2-byte stand-in cert: 07 | len | 01.. fields
        val smallCert = byteArrayOf(0x61, 0x62)
        val bytes = CourierFrame.encode(
            CourierFrame.CONNECT,
            CourierConnect.connectFrame(token, smallCert, nonce, signature).fields
                .map { it.id to it.value },
        )
        // command 7, 4-byte BE length = (32+3)+(1+3)+(1+3)+(2+3)+(17+3)+(8+3) = 79
        assertEquals(0x07, bytes[0].toInt())
        assertEquals(79, ((bytes[1].toInt() and 0xFF) shl 24) or ((bytes[2].toInt() and 0xFF) shl 16) or
            ((bytes[3].toInt() and 0xFF) shl 8) or (bytes[4].toInt() and 0xFF))
        val parsed = CourierFrame.decode(ByteArrayInputStream(bytes))!!
        assertEquals(frameIdsFor(parsed), listOf(1, 2, 5, 12, 13, 14))
    }

    private fun frameIdsFor(frame: CourierFrame.Frame) = frame.fields.map { it.id }

    @Test
    fun connectRootFlagAddsTheGoRootBit() {
        val plain = CourierConnect.connectFrame(token, cert, nonce, signature)
        val root = CourierConnect.connectFrame(
            token, cert, nonce, signature,
            flags = CourierCommands.CONNECT_FLAGS_BASE or CourierCommands.CONNECT_FLAG_ROOT,
        )
        assertEquals(0x41, plain.field(5)!![0].toInt())
        assertEquals(0x45, root.field(5)!![0].toInt())
    }

    @Test
    fun connectRejectsFlagsWithoutTheBase() {
        assertFailsWith<IllegalArgumentException> {
            CourierConnect.connectFrame(token, cert, nonce, signature, flags = 0x04)
        }
    }

    @Test
    fun connectRustVersionFieldIsExplicitAndAppended() {
        val plain = CourierConnect.connectFrame(token, cert, nonce, signature)
        assertNull(plain.field(0x10)) // not sent by default (C57: Rust-only extra)
        val withExtra = CourierConnect.connectFrame(token, cert, nonce, signature, includeRustVersionField = true)
        assertEquals(9, withExtra.field(0x10)!![0].toInt())
        assertEquals(listOf(1, 2, 5, 12, 13, 14, 0x10), frameIdsFor(withExtra))
    }

    @Test
    fun structuredNonceIsTheSpecShape() {
        val nowMillis = 0x00_01_02_03_04_05_06_07
        val nonce = CourierConnect.nonce(CourierConnect.NonceShape.Structured17, nowMillis)
        assertEquals(17, nonce.size)
        assertEquals(0x00, nonce[0].toInt()) // APNs type byte
        for (i in 0 until 8) {
            assertEquals(((nowMillis ushr ((7 - i) * 8)) and 0xFF).toInt(), nonce[1 + i].toInt() and 0xFF)
        }
    }

    @Test
    fun goVariantNonceIs20RandomBytesFirstZeroed() {
        val nonce = CourierConnect.nonce(CourierConnect.NonceShape.Random20FirstByteZeroed)
        assertEquals(20, nonce.size)
        assertEquals(0, nonce[0].toInt()) // first byte zeroed (C57)
    }

    @Test
    fun connectSignatureVerifiesOverTheRawNonceAlone() {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val nonce = CourierConnect.nonce(nowMillis = 1_700_000_000_000)
        val signature = CourierConnect.signature(keyPair.private, nonce)
        assertEquals(0x01, signature[0].toInt())
        assertEquals(0x01, signature[1].toInt())
        val verifier = Signature.getInstance("SHA1withRSA")
        verifier.initVerify(keyPair.public)
        verifier.update(nonce) // signed *alone* — no length-prefixed fields (spec §3.3)
        assertTrue(verifier.verify(signature.copyOfRange(2, signature.size)))
    }

    @Test
    fun filterDefaultShapeIsPerTopicStates() {
        val madrid = CourierCommands.topicHash("com.apple.madrid")
        val sms = CourierCommands.topicHash("com.apple.private.alloy.sms")
        val frame = CourierCommands.filterFrame(token, enabled = listOf(madrid), ignored = listOf(sms))
        assertEquals(CourierFrame.FILTER, frame.command)
        // Rust reading per the §3.3 prose: 1 token, 2 enabled, 3 ignored, 4 opportunistic, 5 paused
        assertContentEquals(listOf(1, 2, 3, 4, 5), frame.fields.map { it.id })
        assertContentEquals(token, frame.field(1))
        assertContentEquals(madrid, frame.field(2))
        assertContentEquals(sms, frame.field(3))
        assertEquals(0, frame.field(4)!!.size)
        assertEquals(0, frame.field(5)!!.size)
    }

    @Test
    fun filterTopicListShapeIsTheGoVariant() {
        val madrid = CourierCommands.topicHash("com.apple.madrid")
        val frame = CourierCommands.filterFrame(token, enabled = listOf(madrid), shape = CourierCommands.FilterShape.TOPIC_LIST)
        assertContentEquals(listOf(1, 2), frame.fields.map { it.id })
        assertContentEquals(madrid, frame.field(2))
    }

    @Test
    fun filterTopicsAreSha1HashesConcatenated() {
        val topics = listOf("com.apple.madrid", "com.apple.private.alloy.sms")
        val frame = CourierCommands.filterFrame(token, enabled = topics.map(CourierCommands::topicHash))
        assertContentEquals(
            topics.map(CourierCommands::topicHash).reduce { a, b -> a + b },
            frame.field(2),
        )
    }

    @Test
    fun sendFrameFieldIdsAndBigEndianMessageId() {
        val payload = byteArrayOf(0x0B, 0x0E, 0x0E, 0x0F)
        val frame = CourierCommands.sendFrame(
            CourierCommands.topicHash("com.apple.madrid"), token, payload, 0x01020304,
        )
        assertEquals(CourierFrame.SEND, frame.command)
        assertContentEquals(listOf(1, 2, 3, 4), frame.fields.map { it.id })
        assertContentEquals(byteArrayOf(1, 2, 3, 4), frame.field(4)) // u32 BE
        assertContentEquals(payload, frame.field(3))
    }

    @Test
    fun ackFrameFieldIds() {
        val frame = CourierCommands.ackFrame(token, 0x01020304, 0)
        assertEquals(CourierFrame.SEND_ACK, frame.command)
        assertContentEquals(listOf(1, 4, 8), frame.fields.map { it.id })
        assertContentEquals(byteArrayOf(0), frame.field(8))
        assertContentEquals(byteArrayOf(1, 2, 3, 4), frame.field(4))
    }

    @Test
    fun setStateCarriesTheRecordedIntervalConstant() {
        val frame = CourierCommands.setStateFrame(1)
        assertEquals(CourierFrame.SET_STATE, frame.command)
        assertContentEquals(listOf(1, 2), frame.fields.map { it.id })
        assertEquals(1, frame.field(1)!![0].toInt())
        assertContentEquals(byteArrayOf(0x7F, 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()), frame.field(2))
    }

    @Test
    fun connectResponseParsesStatusTokenAndTheGoOnlyExtras() {
        val frame = CourierFrame.Frame(
            CourierFrame.CONNECT_RESPONSE,
            listOf(
                CourierFrame.Frame.Field(1, byteArrayOf(0)),
                CourierFrame.Frame.Field(3, ByteArray(32) { 7 }),
                CourierFrame.Frame.Field(4, byteArrayOf(0x10, 0x00)), // 4096
                CourierFrame.Frame.Field(6, byteArrayOf(1, 2, 3)), // capabilities stay raw
                CourierFrame.Frame.Field(8, byteArrayOf(0x3C, 0x00)), // 15360
                CourierFrame.Frame.Field(10, byteArrayOf(0, 0, 0, 0, 0x00, 0x01, 0x02, 0x03)),
            ),
        )
        val response = CourierCommands.parseConnectResponse(frame)
        assertTrue(response.ok())
        assertEquals(4096, response.maxMessageSize)
        assertEquals(15360, response.largeMessageSize)
        assertEquals(0x0000010203, response.serverTimestampMs)
        assertContentEquals(ByteArray(32) { 7 }, response.token)
    }

    @Test
    fun connectResponseInvalidCertStatus() {
        val frame = CourierFrame.Frame(
            CourierFrame.CONNECT_RESPONSE,
            listOf(CourierFrame.Frame.Field(1, byteArrayOf(2))),
        )
        val response = CourierCommands.parseConnectResponse(frame)
        assertEquals(CourierCommands.CONNECT_STATUS_INVALID_CERT, response.status)
        assertTrue(!response.ok())
        assertNull(response.token)
    }

    @Test
    fun connectResponseWithoutStatusFailsLoudly() {
        val frame = CourierFrame.Frame(CourierFrame.CONNECT_RESPONSE, emptyList())
        assertFailsWith<IllegalArgumentException> { CourierCommands.parseConnectResponse(frame) }
    }

    @Test
    fun payloadCommand160IsNotAFrameCommand() {
        // Rev-12 correction: 160 is a `c` value inside command-10 plists (§3.3/§5.1) — the
        // frame layer gives it no special meaning; it decodes as an ordinary unknown command.
        val bytes = CourierFrame.encode(160, listOf(1 to byteArrayOf(9)))
        val frame = CourierFrame.decode(ByteArrayInputStream(bytes))!!
        assertEquals(160, frame.command)
        assertEquals(9, frame.field(1)!![0].toInt())
    }

    @Test
    fun tunnelRequestCarriesTheHeadersPlist() {
        val uuid = ByteArray(16) { it.toByte() }
        val frame = CourierCommands.tunnelRequestFrame(
            "https://query.ess.apple.com/query",
            mapOf("x-protocol-version" to "1640"),
            "text/x-xml-plist",
            byteArrayOf(1, 2, 3),
            uuid,
            CourierCommands.TunnelFieldIds(
                requestUrl = 1, requestHeaders = 2, requestContentType = 3,
                requestBody = 4, requestUuid = 5, replyUuid = 6, replyStatus = 7, replyBody = 8,
            ),
        )
        assertEquals(CourierFrame.TUNNEL_REQUEST, frame.command)
        // The headers field is a binary plist {"h": {...}} — decode with :codec.
        val headers = dev.fenn.imessage.codec.Bplist.decode(frame.field(2)!!)
        val expected = dev.fenn.imessage.codec.BpDict(
            mapOf(
                dev.fenn.imessage.codec.BpString("h") to dev.fenn.imessage.codec.BpDict(
                    mapOf(dev.fenn.imessage.codec.BpString("x-protocol-version") to dev.fenn.imessage.codec.BpString("1640"))
                )
            )
        )
        assertEquals(expected, headers)
    }

    @Test
    fun tunnelResponseParsesUuidStatusBody() {
        val uuid = ByteArray(16) { 9 }
        val frame = CourierFrame.Frame(
            CourierFrame.TUNNEL_RESPONSE,
            listOf(
                CourierFrame.Frame.Field(6, uuid),
                CourierFrame.Frame.Field(7, byteArrayOf(0)),
                CourierFrame.Frame.Field(8, byteArrayOf(4, 5)),
            ),
        )
        val ids = CourierCommands.TunnelFieldIds(
            requestUrl = 1, requestHeaders = 2, requestContentType = 3,
            requestBody = 4, requestUuid = 5, replyUuid = 6, replyStatus = 7, replyBody = 8,
        )
        val response = CourierCommands.parseTunnelResponse(frame, ids)
        assertContentEquals(uuid, response.requestUuid)
        assertEquals(0, response.status)
        assertContentEquals(byteArrayOf(4, 5), response.body)
    }
}
