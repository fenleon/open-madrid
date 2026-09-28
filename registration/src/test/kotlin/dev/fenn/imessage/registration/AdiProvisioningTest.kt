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
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlinx.coroutines.runBlocking

/**
 * Structural tests only: the spec records the ADI exchange's host, its start/finish shape, and
 * that the finish yields machine tokens — no paths, body keys, encodings, or field names
 * (TODO(capture) C6). So these pin the plumbing (requests pass through verbatim, responses
 * surface raw, failures are loud) against scripted transports, never a guessed wire shape.
 */
class AdiProvisioningTest {

    private fun request(url: String = "https://gsa.apple.com/unrecorded-path") = AdiProvisioningRequest(
        url = url,
        headers = mapOf("caller-header" to "caller-value"),
        body = "caller-assembled".toByteArray(),
        contentType = "caller-supplied/type",
    )

    @Test
    fun `start posts the caller-assembled request verbatim`() = runBlocking {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), "ok".toByteArray())))

        AdiProvisioner(http).start(request())

        val call = http.calls.single()
        assertEquals("POST", call.method)
        assertEquals("https://gsa.apple.com/unrecorded-path", call.url)
        assertEquals(mapOf("caller-header" to "caller-value"), call.headers)
        assertEquals("caller-assembled".toByteArray().toList(), call.body.toList())
        assertEquals("caller-supplied/type", call.contentType)
    }

    @Test
    fun `start then finish round-trips in order`() = runBlocking {
        val http = ScriptedIdsHttp(
            listOf(
                IdsHttpResponse(200, mapOf("x-step" to "start"), "start-body".toByteArray()),
                IdsHttpResponse(200, mapOf("x-step" to "finish"), "finish-body".toByteArray()),
            ),
        )
        val provisioner = AdiProvisioner(http)

        val start = provisioner.start(request("https://gsa.apple.com/start"))
        val finish = provisioner.finish(request("https://gsa.apple.com/finish"))

        assertEquals(listOf("https://gsa.apple.com/start", "https://gsa.apple.com/finish"), http.calls.map { it.url })
        assertEquals("start", start.headers["x-step"])
        assertEquals("finish", finish.headers["x-step"])
        assertEquals("finish-body".toByteArray().toList(), finish.body.toList())
    }

    @Test
    fun `plist response surfaces as a raw dict`() = runBlocking {
        val body = "<plist><dict><key>some-field</key><string>value</string></dict></plist>".toByteArray()
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), body)))

        val response = AdiProvisioner(http).start(request())

        assertEquals(mapOf("some-field" to "value"), response.plist)
    }

    @Test
    fun `unrecorded encoding keeps the raw body with no plist - not a silent guess`() = runBlocking {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), "not a plist".toByteArray())))

        val response = AdiProvisioner(http).finish(request())

        assertNull(response.plist)
        assertEquals("not a plist".toByteArray().toList(), response.body.toList())
    }

    @Test
    fun `non-200 fails loudly`() {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(503, emptyMap(), ByteArray(0))))

        runBlocking {
            val exception = assertFailsWith<AdiProvisioningException> { AdiProvisioner(http).start(request()) }
            assertEquals("start-provisioning POST https://gsa.apple.com/unrecorded-path → HTTP 503", exception.message)
        }
    }

    @Test
    fun `the recorded host is pinned as a constant`() {
        assertEquals("gsa.apple.com", AdiProvisioner.GSA_HOST)
    }
}
