package dev.fenn.imessage.ids

import dev.fenn.imessage.codec.NativePlist
import dev.fenn.imessage.courier.CourierCommands
import dev.fenn.imessage.courier.CourierFrame
import java.io.ByteArrayOutputStream
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.util.zip.GZIPOutputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield

/**
 * The §2.1 tunnel command builders and the [CourierTunnelTransport] adapter,
 * scripted end to end: no courier socket, no network — frames go into a list
 * and command-97 responses are fed back through [CourierTunnelTransport
 * .onFrame].
 */
class IdsTunnelTest {

    /** The field-id mapping is caller-supplied (spec §2.1 records the field set, not ids). */
    private val fieldIds = CourierCommands.TunnelFieldIds(
        requestUrl = 3,
        requestHeaders = 4,
        requestContentType = 5,
        requestBody = 6,
        requestUuid = 7,
        replyUuid = 2,
        replyStatus = 3,
        replyBody = 4,
    )

    private val requestUuid = ByteArray(16) { (it + 1).toByte() }

    @Test
    fun tunnelRequestFrameCarriesTheRecordedFieldSet() {
        val headers = mapOf("x-id-self-uri" to "tel:+15551234567", "x-protocol-version" to "1660")

        val frame = CourierCommands.tunnelRequestFrame(
            url = "https://query.ess.apple.com/query",
            headers = headers,
            contentType = "application/x-apple-plist",
            body = byteArrayOf(1, 2, 3),
            requestUuid = requestUuid,
            ids = fieldIds,
        )

        assertEquals(CourierFrame.TUNNEL_REQUEST, frame.command)
        assertEquals(96, frame.command)
        assertEquals("https://query.ess.apple.com/query", frame.field(3)!!.decodeToString())
        // §2.1: the headers ride inside the tunnel payload in a dictionary keyed `h`.
        val headersDict = NativePlist.decode(frame.field(4)!!) as Map<*, *>
        assertEquals(headers, headersDict["h"])
        assertEquals("application/x-apple-plist", frame.field(5)!!.decodeToString())
        assertContentEquals(byteArrayOf(1, 2, 3), frame.field(6))
        assertContentEquals(requestUuid, frame.field(7))
    }

    @Test
    fun tunnelRequestUuidMustBe16Bytes() {
        assertFailsWith<IllegalArgumentException> {
            CourierCommands.tunnelRequestFrame(
                "https://x", emptyMap(), "application/x-apple-plist", ByteArray(0), ByteArray(17), fieldIds,
            )
        }
    }

    @Test
    fun tunnelResponseParsesTheRecordedFieldSet() {
        val frame = CourierFrame.Frame(
            CourierFrame.TUNNEL_RESPONSE,
            listOf(
                CourierFrame.Frame.Field(fieldIds.replyUuid, requestUuid),
                CourierFrame.Frame.Field(fieldIds.replyStatus, byteArrayOf(0)),
                CourierFrame.Frame.Field(fieldIds.replyBody, byteArrayOf(9, 8)),
            ),
        )

        val response = CourierCommands.parseTunnelResponse(frame, fieldIds)

        assertContentEquals(requestUuid, response.requestUuid)
        assertEquals(0, response.status)
        assertContentEquals(byteArrayOf(9, 8), response.body)
    }

    @Test
    fun tunnelResponseParsingRejectsOtherCommandsAndMissingFields() {
        assertFailsWith<IllegalArgumentException> {
            CourierCommands.parseTunnelResponse(CourierFrame.Frame(CourierFrame.SEND, emptyList()), fieldIds)
        }
        assertFailsWith<IllegalArgumentException> {
            CourierCommands.parseTunnelResponse(CourierFrame.Frame(CourierFrame.TUNNEL_RESPONSE, emptyList()), fieldIds)
        }
    }

    @Test
    fun transportCompletesWhenTheMatchingResponseArrives() = runBlocking {
        val sent = mutableListOf<CourierFrame.Frame>()
        val transport = CourierTunnelTransport(fieldIds, sendFrame = { sent.add(it) }, timeoutMs = 5_000)

        val exchange = async { transport.exchange("https://q", mapOf("h" to "v"), byteArrayOf(1), "ct") }
        while (sent.isEmpty()) yield()
        val request = sent.single()
        assertEquals(CourierFrame.TUNNEL_REQUEST, request.command)
        val uuid = request.field(fieldIds.requestUuid)!!
        assertEquals(CourierCommands.TUNNEL_REQUEST_UUID_BYTES, uuid.size)

        transport.onFrame(
            CourierFrame.Frame(
                CourierFrame.TUNNEL_RESPONSE,
                listOf(
                    CourierFrame.Frame.Field(fieldIds.replyUuid, uuid),
                    CourierFrame.Frame.Field(fieldIds.replyStatus, byteArrayOf(0)),
                    CourierFrame.Frame.Field(fieldIds.replyBody, byteArrayOf(7)),
                ),
            ),
        )
        val reply = exchange.await()
        assertEquals(0, reply.status)
        assertContentEquals(byteArrayOf(7), reply.body)
    }

    @Test
    fun transportTimesOutPerTheSpecMinute() = runBlocking {
        val transport = CourierTunnelTransport(fieldIds, sendFrame = {}, timeoutMs = 20)

        val outcome = runCatching {
            transport.exchange("https://q", emptyMap(), ByteArray(0), "ct")
        }.exceptionOrNull()

        assertIs<IdsLookupException>(outcome)
        assertTrue(outcome.message!!.contains("timed out"))
    }

    @Test
    fun aResponseWithNoWaitingRequestIsDropped() = runBlocking {
        val log = mutableListOf<String>()
        val transport = CourierTunnelTransport(fieldIds, sendFrame = {}, logEvent = { log.add(it) })

        transport.onFrame(
            CourierFrame.Frame(
                CourierFrame.TUNNEL_RESPONSE,
                listOf(
                    CourierFrame.Frame.Field(fieldIds.replyUuid, ByteArray(16) { 9 }),
                    CourierFrame.Frame.Field(fieldIds.replyStatus, byteArrayOf(0)),
                ),
            ),
        )
        transport.onFrame(CourierFrame.Frame(CourierFrame.SEND, emptyList())) // not a tunnel response

        assertTrue(log.isNotEmpty())
        // The non-tunnel frame is ignored entirely: no extra log entry beyond the drop.
        assertEquals(1, log.size)
    }

    @Test
    fun lookupOverTheTunnelRoundTripsEndToEnd() = runBlocking {
        val sent = mutableListOf<CourierFrame.Frame>()
        val transport = CourierTunnelTransport(fieldIds, sendFrame = { sent.add(it) }, timeoutMs = 5_000)
        val response = NativePlist.encode(
            mapOf(
                "status" to 0L,
                "results" to mapOf("tel:+15551234567" to mapOf("identities" to emptyList<Any?>())),
            ),
        )
        val gzipped = ByteArrayOutputStream().also { GZIPOutputStream(it).use { g -> g.write(response) } }.toByteArray()

        val outcome = async {
            IdsLookupClient(transport, Bag(mapOf("id-query" to "https://q")), lookupConfig())
                .lookup(listOf("tel:+15551234567"))
        }
        while (sent.isEmpty()) yield()
        val uuid = sent.single().field(fieldIds.requestUuid)!!
        transport.onFrame(
            CourierFrame.Frame(
                CourierFrame.TUNNEL_RESPONSE,
                listOf(
                    CourierFrame.Frame.Field(fieldIds.replyUuid, uuid),
                    CourierFrame.Frame.Field(fieldIds.replyStatus, byteArrayOf(0)),
                    CourierFrame.Frame.Field(fieldIds.replyBody, gzipped),
                ),
            ),
        )

        assertEquals(0, outcome.await().status)
    }

    private fun lookupConfig() = LookupConfig(
        selfUri = "tel:+15557654321",
        pushToken = ByteArray(32),
        protocolVersion = "1660",
        versionUa = "[Test,1,1,Test]",
        signingKey = RSA_KEY.private,
        certificateDer = byteArrayOf(0x30, 0x82.toByte(), 0x01, 0x00),
    )

    private companion object {
        /** Test-only key, generated per class — never a hardcoded key. */
        val RSA_KEY: KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair()
    }
}

/** The private-IDS push routing of §2.3 as the engine's frame handler sees it. */
class PrivateIdsPushTest {

    private fun idsPushFrame(body: String): CourierFrame.Frame =
        CourierCommands.sendFrame(
            CourierCommands.topicHash(PrivateIdsPush.TOPIC),
            ByteArray(32),
            body.toByteArray(),
            messageId = 1,
        )

    @Test
    fun extractsTheCommandCountFromAnIdsTopicPush() {
        assertEquals(34, PrivateIdsPush.commandFromFrame(idsPushFrame("""{"c":34}""")))
    }

    @Test
    fun ignoresOtherTopics() {
        val frame = CourierCommands.sendFrame(
            CourierCommands.topicHash("com.apple.madrid"), ByteArray(32), """{"c":34}""".toByteArray(), 1,
        )
        assertNull(PrivateIdsPush.commandFromFrame(frame))
    }

    @Test
    fun ignoresNonSendFramesAndMalformedBodies() {
        assertNull(PrivateIdsPush.commandFromFrame(CourierFrame.Frame(CourierFrame.KEEPALIVE_ACK, emptyList())))
        assertNull(PrivateIdsPush.commandFromFrame(idsPushFrame("not json")))
        assertNull(PrivateIdsPush.commandFromFrame(idsPushFrame("""{"other":1}""")))
    }
}
