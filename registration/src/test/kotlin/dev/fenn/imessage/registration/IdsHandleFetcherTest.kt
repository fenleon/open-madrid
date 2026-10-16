package dev.fenn.imessage.registration

import dev.fenn.imessage.codec.XmlPlist
import dev.fenn.imessage.ids.Bag
import dev.fenn.imessage.ids.IdsHttpResponse
import dev.fenn.imessage.ids.IdsSigning
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

class IdsHandleFetcherTest {

    private val url = "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/getHandles"
    private val pushToken = ByteArray(32) { it.toByte() }
    private val pushCert = byteArrayOf(0x30, 0x82.toByte(), 0x02, 0x00)
    private val authCert = byteArrayOf(0x30, 0x82.toByte(), 0x03, 0x00)

    private fun fetcher(http: ScriptedIdsHttp) = IdsHandleFetcher(
        http,
        Bag(mapOf(IdsHandleFetcher.BAG_KEY to url)),
        RegisterConfig(
            pushToken = pushToken,
            pushKey = PUSH.private,
            pushCertificateDer = pushCert,
            protocolVersion = "1660",
            userAgent = "com.apple.invitation-registration [Test,1,1,Test]",
        ),
    )

    private fun handlesResponse(status: Long = 0L, uris: List<String> = listOf("tel:+15557654321")) = XmlPlist.encode(
        mapOf(
            "status" to status,
            "handles" to uris.map { mapOf("uri" to it) },
        ),
    )

    @Test
    fun theRequestIsABodilessGetSignedByBothIdentitiesWithoutAnIndex() = runBlocking {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), handlesResponse())))
        fetcher(http).handles("D:10000000000", AUTH.private, authCert)

        val call = http.calls.single()
        assertEquals("GET", call.method)
        assertEquals(url, call.url)
        assertEquals("1660", call.headers.getValue("x-protocol-version"))
        assertEquals(Base64.getEncoder().encodeToString(pushToken), call.headers.getValue("x-push-token"))
        assertEquals("D:10000000000", call.headers.getValue("x-auth-user-id"))
        // No user-agent: the reference's id-get-handles request carries none (user.rs:712 base_request).
        assertFalse(call.headers.containsKey("user-agent"), "the reference sends no user-agent on id-get-handles")
        assertFalse(call.headers.keys.any { it.endsWith("-0") }, "base_request signs with item=None: no index postfix")

        // The signed tuple is the same shape as the register's: bag key, empty query, empty body, push token.
        val fields = listOf(IdsHandleFetcher.BAG_KEY.toByteArray(), ByteArray(0), ByteArray(0), pushToken)
        verifySignature(call, "x-push-nonce", "x-push-sig", PUSH, fields)
        verifySignature(call, "x-auth-nonce", "x-auth-sig", AUTH, fields)
    }

    @Test
    fun theHandlesComeBackInWireOrder() = runBlocking {
        val http = ScriptedIdsHttp(
            listOf(IdsHttpResponse(200, emptyMap(), handlesResponse(uris = listOf("tel:+15557654321", "mailto:user@example.com")))),
        )
        assertEquals(
            listOf("tel:+15557654321", "mailto:user@example.com"),
            fetcher(http).handles("D:1", AUTH.private, authCert),
        )
    }

    @Test
    fun aNonZeroStatusFailsLoudly() = runBlocking {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), handlesResponse(status = 6005L))))
        val failure = assertFailsWith<IdsActivationException> {
            fetcher(http).handles("D:1", AUTH.private, authCert)
        }
        assertTrue(failure.message!!.contains("6005"), failure.message)
    }

    private fun verifySignature(
        call: ScriptedIdsHttp.Call,
        nonceHeader: String,
        sigHeader: String,
        key: KeyPair,
        fields: List<ByteArray>,
    ) {
        val nonce = Base64.getDecoder().decode(call.headers.getValue(nonceHeader))
        assertEquals(IdsSigning.NONCE_BYTES, nonce.size)
        assertEquals(IdsSigning.TYPE_HTTPS, nonce[0])
        val signature = Base64.getDecoder().decode(call.headers.getValue(sigHeader))
        assertContentEquals(IdsSigning.SIGNATURE_PREFIX_BYTES, signature.copyOfRange(0, 2))
        val verifier = Signature.getInstance("SHA1withRSA")
        verifier.initVerify(key.public)
        verifier.update(IdsSigning.signingBytes(nonce, fields))
        assertTrue(verifier.verify(signature.copyOfRange(2, signature.size)), "$sigHeader does not verify")
    }

    private companion object {
        val PUSH: KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair()
        val AUTH: KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair()
    }
}
