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

/**
 * §1.5 response-header token parsing (`X-Apple-GS-Token` / `X-Apple-HB-Token` /
 * `X-Apple-PE-Token`): base64 of colon-separated `ID:TOKEN[:DURATION][:EXP]` with inconsistent
 * trailer forms — the recorded heuristic is pinned here, including the edge forms.
 */
class GsaTokensTest {

    private val now = 1_770_000_000_000L

    private fun token(vararg fields: String): String =
        Base64.getEncoder().encodeToString(fields.joinToString(":").toByteArray())

    @Test
    fun `bare ID-TOKEN has no expiry`() {
        val parsed = GsaTokenHeaders.parse("x-apple-gs-token", token("svc.one", "tok1"), now)
        assertEquals(1, parsed.size)
        assertEquals("svc.one", parsed[0].serviceId)
        assertEquals("tok1", parsed[0].token)
        assertNull(parsed[0].durationSeconds)
        assertNull(parsed[0].expiresAtEpochMs)
    }

    @Test
    fun `single trailer reads as expiry - epoch-ms passes through, epoch-seconds is scaled`() {
        val ms = GsaTokenHeaders.parse("x-apple-gs-token", token("svc", "tok", "1800000000000"), now).single()
        assertEquals(1_800_000_000_000L, ms.expiresAtEpochMs)

        val s = GsaTokenHeaders.parse("x-apple-gs-token", token("svc", "tok", "1800000000"), now).single()
        assertEquals(1_800_000_000_000L, s.expiresAtEpochMs)
    }

    @Test
    fun `two trailers are DURATION then EXP`() {
        val parsed = GsaTokenHeaders.parse(
            "x-apple-gs-token",
            token("svc", "tok", "300", "1800000000000"),
            now,
        ).single()
        assertEquals(300L, parsed.durationSeconds)
        assertEquals(1_800_000_000_000L, parsed.expiresAtEpochMs)
    }

    @Test
    fun `comma-joined repeats parse per occurrence`() {
        val value = token("svc.one", "tok1") + ", " + token("svc.two", "tok2", "1800000000000")
        val parsed = GsaTokenHeaders.parse("x-apple-gs-token", value, now)
        assertEquals(listOf("svc.one", "svc.two"), parsed.map { it.serviceId })
        assertEquals("tok1", parsed[0].token)
        assertEquals(1_800_000_000_000L, parsed[1].expiresAtEpochMs)
    }

    @Test
    fun `non-numeric trailer surfaces as null rather than failing - the forms are inconsistent`() {
        val parsed = GsaTokenHeaders.parse("x-apple-gs-token", token("svc", "tok", "tomorrow"), now).single()
        assertNull(parsed.expiresAtEpochMs)
    }

    @Test
    fun `payload without the ID-TOKEN shape fails loudly`() {
        val bad = Base64.getEncoder().encodeToString("just-a-token".toByteArray())
        assertFailsWith<GsaLoginException> { GsaTokenHeaders.parse("x-apple-gs-token", bad, now) }
    }

    @Test
    fun `undecodable base64 fails loudly`() {
        assertFailsWith<GsaLoginException> { GsaTokenHeaders.parse("x-apple-gs-token", "!!!not-base64!!!", now) }
    }

    @Test
    fun `gs tokens key by service id`() {
        val value = token("svc.one", "tok1") + "," + token("svc.two", "tok2")
        val tokens = GsaTokenHeaders.gsTokens(value, now)
        assertEquals("tok1", tokens.getValue("svc.one").token)
        assertEquals("tok2", tokens.getValue("svc.two").token)
        assertEquals(emptyMap<String, GsaTokenHeader>(), GsaTokenHeaders.gsTokens(null, now))
    }

    @Test
    fun `pet uses the trailer expiry when present`() {
        val pet = GsaTokenHeaders.pet(token("com.apple.gs.idms.pet", "pet-token", "1800000000000"), now)
        assertEquals("pet-token", pet?.token)
        assertEquals(1_800_000_000_000L, pet?.expiresAtEpochMs)
    }

    @Test
    fun `pet defaults to the recorded 300 s when the header carries no trailer`() {
        val pet = GsaTokenHeaders.pet(token("com.apple.gs.idms.pet", "pet-token"), now)
        assertEquals("pet-token", pet?.token)
        assertEquals(now + 300_000, pet?.expiresAtEpochMs)
    }

    @Test
    fun `pet absent header gives no pet`() {
        assertNull(GsaTokenHeaders.pet(null, now))
        assertNull(GsaTokenHeaders.pet("", now))
    }
}
