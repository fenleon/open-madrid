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

/**
 * §1.5 spd decryption. Key/IV labels and a full decrypt sample are known answers from the
 * independent dev script; the sample plist exercises the recorded field reads (`t`, `DsPrsId`,
 * `adsid`, `acname`) and the structural `t`-entry read.
 */
class GsaSpdTest {

    /** HMAC-SHA256(K, "extra data key:") for the s2k KAT session key K (dev-script KAT). */
    private val katK = "92f6de387c217ae9dc61911d532234e6a1fdbc343c18081b55b4dd1d33f84700".fromHex()

    @Test
    fun `key and iv labels known answers`() {
        assertEquals("3b6513fa04855fd56c396dffaec2fb549e50fd1a1b67c12553042994389521b3", GsaSpdDecryptor.key(katK).toHex())
        assertEquals("7752dd0de4323335fe328fe70b7471d2", GsaSpdDecryptor.iv(katK).toHex())
    }

    @Test
    fun `decrypts the sample spd and reads the recorded fields`() {
        val raw = GsaSpdDecryptor.decrypt(SAMPLE_SPD, katK)
        val spd = GsaSpd.parse(raw)
        assertEquals(123456789L, spd.dsPrsId)
        assertEquals("001234.abcdef.987", spd.adsid)
        assertEquals("user@example.com", spd.accountName)
        assertEquals(setOf("GsIdmsToken"), spd.tokens.keys)
        val token = spd.serviceToken("GsIdmsToken")
        assertEquals("the-idms-token", token.token)
        assertEquals(1_800_000_000_000L, token.expiresAtEpochMs) // `expiry` = epoch-ms
        assertEquals(null, token.durationSeconds)
    }

    @Test
    fun `top-level GsIdmsToken and fn-ln are read per the recorded keys`() {
        val raw = linkedMapOf<String, Any?>(
            "t" to linkedMapOf<String, Any?>(
                "com.apple.gs.idms.pet" to linkedMapOf<String, Any?>(
                    "token" to "pet-token",
                    "duration" to 600L,
                ),
            ),
            "GsIdmsToken" to "idms-token",
            "fn" to "Ada",
            "ln" to "Lovelace",
        )
        val spd = GsaSpd.parse(raw)
        assertEquals("idms-token", spd.gsIdmsToken)
        assertEquals("Ada", spd.firstName)
        assertEquals("Lovelace", spd.lastName)
        val pet = spd.serviceToken("com.apple.gs.idms.pet")
        assertEquals("pet-token", pet.token)
        assertEquals(null, pet.expiresAtEpochMs)
        assertEquals(600L, pet.durationSeconds)
    }

    @Test
    fun `identity token is base64 of adsid colon idms token`() {
        assertEquals(
            "MDAxMjM0LmFiY2RlZi45ODc6dGhlLWlkbXMtdG9rZW4=",
            gsaIdentityToken("001234.abcdef.987", "the-idms-token"),
        )
    }

    @Test
    fun `wrong session key fails loudly`() {
        val other = katK.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFailsWith<GsaLoginException> { GsaSpdDecryptor.decrypt(SAMPLE_SPD, other) }
    }

    @Test
    fun `token map missing or non-dict fails loudly`() {
        val raw = GsaSpdDecryptor.decrypt(SAMPLE_SPD, katK) - "t"
        assertFailsWith<GsaLoginException> { GsaSpd.parse(raw) }
    }

    @Test
    fun `t entries without the recorded keys fail loudly`() {
        val noToken = linkedMapOf<String, Any?>(
            "t" to linkedMapOf<String, Any?>("svc" to linkedMapOf<String, Any?>("expiry" to 1L)),
        )
        val noExpiry = linkedMapOf<String, Any?>(
            "t" to linkedMapOf<String, Any?>("svc" to linkedMapOf<String, Any?>("token" to "t")),
        )
        assertFailsWith<GsaLoginException> { GsaSpd.parse(noToken) }
        assertFailsWith<GsaLoginException> { GsaSpd.parse(noExpiry) }
    }

    private fun String.fromHex(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }

    companion object {
        /** Dev-script-encrypted sample spd (AES-256-CBC/PKCS7 under the s2k KAT session key). */
        val SAMPLE_SPD: ByteArray = Base64.getDecoder().decode(
            "jv+SLJj1p8uywkkSXwYzBnOSWwDHKTb2CPqomQQ3JwDmey1di35tjbIFU4EnRbkGCHgEHrALs0KWpF1Ni+N5VCVhkEPm5zHFv" +
                "H4A5BeX7JBln/hilrKErWRFMofWlgVQWcINpKErTN+hhv6gMQtVtv9rmH3LiOOs2aD/I/1K0dbOw7T601GRBoRsOzsddXwX" +
                "fThSNbgYbfksF11U6SFnSvKFgSqADsRldpEVj3qZQnFbRM/U2MaS7fTJqgPkinKfeKvpK+wlzqOCY9XomUj+Y8Yb14paGBX" +
                "1IDCH+pPx5pqrtsnFNsIluzt2MZcOVGmRePtUhLrw6Yb9MMN5JbtFT8Z9RtW1TDhudfMnvPT1tRcVHJ1EF6aF/ZYdtvPnKq" +
                "6nWgyB0IqB65ie+0JEXcPRRBe4ojK4zKNVYeDrjhjz+Sq/rHamYf39qUkYXZNhAYjtCABUBoQbg/ArO1rLAJ7w8NGe1ivfl" +
                "krw3gYD6F1/cuGhe/LOO4HKajw3t+sjaIDW",
        )
    }
}
