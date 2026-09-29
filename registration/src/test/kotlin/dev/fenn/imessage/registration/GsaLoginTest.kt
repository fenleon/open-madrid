package dev.fenn.imessage.registration

import dev.fenn.imessage.codec.NativePlist
import dev.fenn.imessage.codec.Plist
import dev.fenn.imessage.codec.PlistDate
import dev.fenn.imessage.codec.PlistFormatException
import dev.fenn.imessage.codec.XmlPlist
import dev.fenn.imessage.codec.integerOrNull
import dev.fenn.imessage.codec.longOrNull
import dev.fenn.imessage.codec.stringKeyedDictOrNull
import dev.fenn.imessage.codec.typeName
import dev.fenn.imessage.courier.CourierClient
import dev.fenn.imessage.courier.CourierCommands
import dev.fenn.imessage.courier.CourierFrame
import dev.fenn.imessage.ids.AppleTrust
import dev.fenn.imessage.ids.Bag
import dev.fenn.imessage.ids.BagKeyMissingException
import dev.fenn.imessage.ids.IdsBagFetcher
import dev.fenn.imessage.ids.IdsHttp
import dev.fenn.imessage.ids.IdsHttpResponse
import dev.fenn.imessage.ids.IdsIdentity
import dev.fenn.imessage.ids.IdsLookupClient
import dev.fenn.imessage.ids.IdsLookupException
import dev.fenn.imessage.ids.IdsLookupResult
import dev.fenn.imessage.ids.IdsSigning
import dev.fenn.imessage.ids.TunnelReply
import dev.fenn.imessage.ids.TunnelStatus
import dev.fenn.imessage.crypto.EcCrypto
import dev.fenn.imessage.crypto.MessageBody
import dev.fenn.imessage.crypto.PairEcEnvelope
import dev.fenn.imessage.crypto.PairEnvelope
import dev.fenn.imessage.crypto.PayloadCommands
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * The §1.5 GSA SRP POSTs: endpoint, content type, the `Header`/`Request` XML-plist wrapper,
 * request key sets, response parsing (`s`/`B`/`i`/`c`/`sp`/`Status`; `M2`/`spd`/`au`), the
 * `sp` default, and Status.ec error surfacing — all against scripted transports.
 */
class GsaLoginTest {

    private val okInit = XmlPlist.encode(
        mapOf(
            "Response" to linkedMapOf<String, Any?>(
                "s" to byteArrayOf(1, 2, 3),
                "B" to byteArrayOf(4, 5, 6),
                "i" to 1000L,
                "c" to "challenge-string",
                "sp" to "s2k_fo",
                "Status" to linkedMapOf<String, Any?>("ec" to 0L, "em" to ""),
            ),
        ),
    )

    private fun client(responses: List<IdsHttpResponse>) =
        GsaLoginClient(ScriptedIdsHttp(responses), endpoint = "https://gsa.example/GsService2")

    private fun initRequest() = GsaInitRequest(
        username = "user@example.com",
        a2k = byteArrayOf(9),
        cpd = mapOf("cou" to "US"),
        headers = mapOf("X-Apple-I-MD" to "otp"),
    )

    @Test
    fun `init posts the recorded wrapper and key set`() = runBlocking {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), okInit)))
        GsaLoginClient(http, endpoint = "https://gsa.example/GsService2").init(initRequest())

        val call = http.calls.single()
        assertEquals("POST", call.method)
        assertEquals("https://gsa.example/GsService2", call.url)
        assertEquals("text/x-xml-plist", call.contentType)
        assertEquals(mapOf("X-Apple-I-MD" to "otp"), call.headers)
        val body = XmlPlist.decode(call.body) as Map<*, *>
        assertEquals(mapOf("Version" to "1.0.1"), body["Header"])
        val request = body["Request"] as Map<*, *>
        assertEquals("user@example.com", request["u"])
        assertEquals("init", request["o"])
        assertEquals(listOf("s2k", "s2k_fo"), request["ps"])
        assertEquals(mapOf("cou" to "US"), request["cpd"])
        assertTrue(request["A2k"] is ByteArray)
        assertEquals(setOf("A2k", "cpd", "o", "ps", "u"), request.keys)
    }

    @Test
    fun `init response parses the recorded fields`() = runBlocking {
        val response = client(listOf(IdsHttpResponse(200, emptyMap(), okInit))).init(initRequest())
        assertEquals(byteArrayOf(1, 2, 3).toList(), response.salt.toList())
        assertEquals(byteArrayOf(4, 5, 6).toList(), response.serverPublic.toList())
        assertEquals(1000, response.iterations)
        assertEquals("challenge-string", response.challenge)
        assertEquals("s2k_fo", response.protocol)
        assertEquals(0, response.status.ec)
    }

    @Test
    fun `missing sp defaults to s2k`() = runBlocking {
        val withoutSp = XmlPlist.encode(
            mapOf(
                "Response" to linkedMapOf<String, Any?>(
                    "s" to byteArrayOf(1),
                    "B" to byteArrayOf(2),
                    "i" to 2000L,
                    "c" to "c",
                    "Status" to linkedMapOf<String, Any?>("ec" to 0L),
                ),
            ),
        )
        val response = client(listOf(IdsHttpResponse(200, emptyMap(), withoutSp))).init(initRequest())
        assertEquals("s2k", response.protocol)
    }

    @Test
    fun `non-zero ec surfaces loudly with the recorded message`() = runBlocking {
        val rejected = XmlPlist.encode(
            mapOf(
                "Response" to mapOf(
                    "Status" to linkedMapOf<String, Any?>("ec" to -20001L, "em" to "bad credentials"),
                ),
            ),
        )
        val exception = assertFailsWith<GsaLoginException> {
            runBlocking { client(listOf(IdsHttpResponse(200, emptyMap(), rejected))).init(initRequest()) }
        }
        assertTrue(exception.message!!.contains("ec=-20001"), exception.message)
        assertTrue(exception.message!!.contains("bad credentials"), exception.message)
    }

    @Test
    fun `non-200 fails loudly`() = runBlocking {
        val exception = assertFailsWith<GsaLoginException> {
            client(listOf(IdsHttpResponse(503, emptyMap(), ByteArray(0)))).init(initRequest())
        }
        assertTrue(exception.message!!.contains("HTTP 503"))
    }

    @Test
    fun `missing recorded fields fail loudly`() = runBlocking {
        val noSalt = XmlPlist.encode(
            mapOf(
                "Response" to mapOf(
                    "B" to byteArrayOf(2),
                    "i" to 1000L,
                    "c" to "c",
                    "Status" to linkedMapOf<String, Any?>("ec" to 0L),
                ),
            ),
        )
        val exception = assertFailsWith<GsaLoginException> {
            client(listOf(IdsHttpResponse(200, emptyMap(), noSalt))).init(initRequest())
        }
        assertTrue(exception.message!!.contains("'s'"))
    }

    @Test
    fun `complete posts the recorded key set and parses the response`() = runBlocking {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), okComplete())))
        val response = GsaLoginClient(http, endpoint = "https://gsa.example/GsService2")
            .complete(
                GsaCompleteRequest(
                    username = "user@example.com",
                    m1 = byteArrayOf(7),
                    challenge = "challenge-string",
                    cpd = mapOf("cou" to "US"),
                ),
                nowEpochMs = 1_000_000L,
            )

        val call = http.calls.single()
        assertEquals("text/x-xml-plist", call.contentType)
        val body = XmlPlist.decode(call.body) as Map<*, *>
        val request = body["Request"] as Map<*, *>
        assertEquals("complete", request["o"])
        assertEquals("user@example.com", request["u"])
        assertEquals("challenge-string", request["c"])
        assertEquals(byteArrayOf(7).toList(), (request["M1"] as ByteArray).toList())
        assertEquals(setOf("M1", "c", "cpd", "o", "u"), request.keys)

        assertEquals(byteArrayOf(8).toList(), response.m2!!.toList())
        assertEquals(byteArrayOf(9).toList(), response.spd!!.toList())
        assertNull(response.secondaryAuth)
        assertNull(response.pet)
    }

    @Test
    fun `complete parses the PET from the response headers`() = runBlocking {
        val petValue = Base64.getEncoder()
            .encodeToString("com.apple.gs.idms.pet:pet-token:1800000000000".toByteArray())
        val response = client(
            listOf(
                IdsHttpResponse(
                    200,
                    mapOf("X-Apple-PE-Token" to petValue),
                    okComplete(au = null),
                ),
            ),
        ).complete(completeRequest(), nowEpochMs = 1_000_000L)
        assertEquals("pet-token", response.pet?.token)
        assertEquals(1_800_000_000_000L, response.pet?.expiresAtEpochMs)
    }

    @Test
    fun `au without an error code surfaces as secondary auth`() = runBlocking {
        val response = client(listOf(IdsHttpResponse(200, emptyMap(), okComplete(au = "secondaryAuth"))))
            .complete(completeRequest(), nowEpochMs = 1_000_000L)
        assertEquals("secondaryAuth", response.secondaryAuth)
    }

    private fun completeRequest() = GsaCompleteRequest("user@example.com", byteArrayOf(7), "c", emptyMap())

    private fun okComplete(au: String? = null): ByteArray {
        val status = linkedMapOf<String, Any?>("ec" to 0L)
        au?.let { status["au"] = it }
        val response = linkedMapOf<String, Any?>(
            "M2" to byteArrayOf(8),
            "spd" to byteArrayOf(9),
            "Status" to status,
        )
        return XmlPlist.encode(mapOf("Response" to response))
    }
}
