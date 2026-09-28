package dev.fenn.imessage.ids

import java.io.ByteArrayOutputStream
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64
import java.util.zip.GZIPOutputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import dev.fenn.imessage.codec.NativePlist

/** Scripted [LookupTransport] — the tunnel is faked, never the network. */
class ScriptedLookupTransport(replies: List<TunnelReply>) : LookupTransport {

    class Call(val url: String, val headers: Map<String, String>, val body: ByteArray, val contentType: String)

    val calls = mutableListOf<Call>()
    private val replies = replies.toList()
    private var next = 0

    override suspend fun exchange(
        url: String,
        headers: Map<String, String>,
        body: ByteArray,
        contentType: String,
    ): TunnelReply {
        calls.add(Call(url, headers, body, contentType))
        return replies[next++]
    }
}

class IdsLookupTest {

    private val idQueryUrl = "https://query.ess.apple.com/WebObjects/QueryService.woa/wa/query"
    private val handle = "+15551234567"
    private val pushToken = ByteArray(32) { it.toByte() }
    private val certificateDer = byteArrayOf(0x30, 0x82.toByte(), 0x01, 0x00)
    private val versionUa = "com.apple.invitation-registration [Test,1,1,Test]"

    private fun config(subService: String? = null) = LookupConfig(
        selfUri = "tel:+15557654321",
        pushToken = pushToken,
        protocolVersion = "1660",
        versionUa = versionUa,
        signingKey = RSA_KEY.private,
        certificateDer = certificateDer,
        subService = subService,
    )

    private fun bag() = Bag(mapOf("id-query" to idQueryUrl))

    private fun transport(vararg replies: TunnelReply) =
        ScriptedLookupTransport(replies.toList())

    /** §2.1: the response is a gzipped plist. */
    private fun gzip(bytes: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        GZIPOutputStream(out).use { it.write(bytes) }
        return out.toByteArray()
    }

    /** C48-closed response shape: top-level `status` + `results`, handle-keyed. */
    private fun responseBody(status: Int = 0): ByteArray = NativePlist.encode(
        mapOf(
            "status" to status.toLong(),
            "results" to mapOf(
                handle to mapOf(
                    "status" to 0L,
                    "sender-correlation-identifier" to "corr",
                    "kt-account-key" to ByteArray(32) { 9 },
                    "identities" to listOf(
                        mapOf(
                            "client-data" to mapOf(
                                "public-message-identity-key" to ByteArray(65) { 1 },
                                "public-message-ngm-device-prekey-data-key" to ByteArray(32) { 2 },
                                "ngm-public-identity" to ByteArray(33) { 3 },
                                "supports-certified-delivery-v1" to true,
                            ),
                            "kt-loggable-data" to ByteArray(16) { 4 },
                            "push-token" to ByteArray(32) { 1 },
                            "session-token" to "opaque-session-token",
                            "session-token-expires-seconds" to 3600L,
                            "session-token-refresh-seconds" to 1800L,
                        ),
                    ),
                ),
                "not-registered@example.com" to mapOf("status" to 3L, "identities" to emptyList<Any?>()),
            ),
        ),
    )

    @Test
    fun requestIsSignedAndAddressedToTheBagUrl() = runBlocking {
        val t = transport(TunnelReply(0, gzip(responseBody())))
        val uris = listOf("tel:$handle")

        IdsLookupClient(t, bag(), config()).lookup(uris)

        val call = t.calls.single()
        assertEquals(idQueryUrl, call.url)
        assertEquals("application/x-apple-plist", call.contentType)

        // The signed tuple of §1.4: (bag key, empty query, exact request body, raw push token).
        val nonce = Base64.getDecoder().decode(call.headers.getValue("x-id-nonce"))
        assertEquals(17, nonce.size)
        assertEquals(0x01, nonce[0].toInt())
        val fields = listOf("id-query".toByteArray(), ByteArray(0), call.body, pushToken)
        val verifier = Signature.getInstance("SHA1withRSA")
        verifier.initVerify(RSA_KEY.public)
        verifier.update(IdsSigning.signingBytes(nonce, fields))
        val signature = Base64.getDecoder().decode(call.headers.getValue("x-id-sig"))
        assertContentEquals(byteArrayOf(0x01, 0x01), signature.copyOfRange(0, 2))
        assertTrue(verifier.verify(signature.copyOfRange(2, signature.size)), "x-id-sig does not verify")
        assertContentEquals(certificateDer, Base64.getDecoder().decode(call.headers.getValue("x-id-cert")))
    }

    @Test
    fun headersCarryTheC47ClosedWireNames() = runBlocking {
        val t = transport(TunnelReply(0, gzip(responseBody())))

        IdsLookupClient(t, bag(), config()).lookup(listOf("tel:$handle"))

        val headers = t.calls.single().headers
        assertEquals("tel:+15557654321", headers.getValue("x-id-self-uri"))
        assertEquals("1660", headers.getValue("x-protocol-version"))
        assertEquals(
            "${IdsLookupClient.USER_AGENT_PREFIX} $versionUa",
            headers.getValue("user-agent"),
        )
        assertEquals(Base64.getEncoder().encodeToString(pushToken), headers.getValue("x-push-token"))
        // The opt-in flags of §2.1, both true "in most calls" — the default here.
        assertEquals("true", headers.getValue("x-required-for-message"))
        assertEquals("true", headers.getValue("x-result-expected"))
    }

    @Test
    fun subServiceHeaderRidesOnlyWhenConfigured() = runBlocking {
        val with = transport(TunnelReply(0, gzip(responseBody())))
        val without = transport(TunnelReply(0, gzip(responseBody())))

        IdsLookupClient(with, bag(), config(subService = "com.apple.private.alloy.sms"))
            .lookup(listOf("tel:$handle"))
        IdsLookupClient(without, bag(), config()).lookup(listOf("tel:$handle"))

        assertEquals("com.apple.private.alloy.sms", with.calls.single().headers.getValue("x-id-sub-service"))
        assertFalse(without.calls.single().headers.containsKey("x-id-sub-service"))
    }

    @Test
    fun requestBodyCarriesPlainHandleStringsNotRegisterStyleDicts() = runBlocking {
        val t = transport(TunnelReply(0, gzip(responseBody())))
        val uris = listOf("tel:$handle", "mailto:user@example.com")

        IdsLookupClient(t, bag(), config()).lookup(uris)

        val decoded = NativePlist.decode(t.calls.single().body) as Map<*, *>
        assertEquals(uris, decoded["uris"])
        assertTrue((decoded["uris"] as List<*>).all { it is String }, "uris elements must be plain strings")
    }

    @Test
    fun gzippedResponseParsesTopLevelStatusAndHandleKeyedResults() = runBlocking {
        val t = transport(TunnelReply(0, gzip(responseBody())))

        val response = IdsLookupClient(t, bag(), config()).lookup(listOf("tel:$handle"))

        assertEquals(0, response.status)
        val result = response.results.getValue(handle)
        assertEquals(1, result.identities.size)
        assertEquals(3600L, result.identities[0].expiresSeconds)
        assertEquals(1800L, result.identities[0].refreshSeconds)
        // C48-closed keys ride in raw, typed only where the flow needs them.
        assertEquals("opaque-session-token", result.identities[0].raw["session-token"])
        assertEquals("corr", result.raw["sender-correlation-identifier"])
        assertTrue(result.raw.containsKey("kt-account-key"))
        val clientData = result.identities[0].raw["client-data"] as Map<*, *>
        assertTrue(clientData.containsKey("public-message-identity-key"))
        assertTrue(clientData.containsKey("public-message-ngm-device-prekey-data-key"))
        assertTrue(clientData.containsKey("ngm-public-identity"))
        assertTrue(clientData.containsKey("supports-certified-delivery-v1"))

        val empty = response.results.getValue("not-registered@example.com")
        assertEquals(3, empty.status)
        assertEquals(0, empty.identities.size)
    }

    @Test
    fun ungzippedResponseParsesToo() = runBlocking {
        val t = transport(TunnelReply(0, responseBody()))

        val response = IdsLookupClient(t, bag(), config()).lookup(listOf("tel:$handle"))

        assertEquals(3600L, response.results.getValue(handle).identities[0].expiresSeconds)
    }

    @Test
    fun topLevelStatusIsSurfacedIncludingErrorCodes() = runBlocking {
        // Port note: the constant lived in the un-ported orchestration file — the spec value
        // 5206 ("response too large", §2.1) is inlined here.
        val t = transport(TunnelReply(0, gzip(responseBody(status = 5206))))

        val response = IdsLookupClient(t, bag(), config()).lookup(listOf("tel:$handle"))

        assertEquals(5206, response.status)
    }

    @Test
    fun absentPerHandleStatusParsesLeniently() = runBlocking {
        val bytes = NativePlist.encode(
            mapOf(
                "status" to 0L,
                "results" to mapOf(handle to mapOf("identities" to emptyList<Any?>())),
            ),
        )
        val t = transport(TunnelReply(0, bytes))

        val response = IdsLookupClient(t, bag(), config()).lookup(listOf("tel:$handle"))

        // C55: neither reference client reads a per-handle status — absence is not an error.
        assertEquals(0, response.results.getValue(handle).status)
    }

    @Test
    fun nonZeroTunnelStatusThrows() {
        val t = transport(TunnelReply(7, gzip(responseBody())))

        assertFailsWith<IdsLookupException> {
            runBlocking { IdsLookupClient(t, bag(), config()).lookup(listOf("tel:$handle")) }
        }
    }

    @Test
    fun unparseableBodyThrows() {
        val t = transport(TunnelReply(0, "not a plist".toByteArray()))

        assertFailsWith<IdsLookupException> {
            runBlocking { IdsLookupClient(t, bag(), config()).lookup(listOf("tel:$handle")) }
        }
    }

    @Test
    fun missingIdQueryKeyIsTheBagError() {
        val t = transport()
        val client = IdsLookupClient(t, Bag(emptyMap()), config())

        assertFailsWith<BagKeyMissingException> {
            runBlocking { client.lookup(listOf("tel:$handle")) }
        }
        assertEquals(0, t.calls.size)
    }

    private companion object {
        /** Test-only key, generated per class — never a hardcoded key. */
        val RSA_KEY: KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair()
    }
}
