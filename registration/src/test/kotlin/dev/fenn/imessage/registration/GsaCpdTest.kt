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
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The §1.5 cpd dictionary: anisette values as keys (from chunk A's provider output), the
 * derived `X-Apple-I-MD-LU` (§1.1), and the recorded fixed-value set — pinned wholesale, since
 * the server compares this dict byte-for-byte.
 */
class GsaCpdTest {

    private val anisette = mapOf(
        "X-Apple-I-Client-Time" to "2026-09-11T12:00:00Z",
        "X-Apple-I-TimeZone" to "UTC",
        "X-Apple-Locale" to "en_US",
        "X-Apple-I-MD-RINFO" to "17106176",
        "X-Mme-Device-Id" to "1234ABCD-5678-90EF-1234-ABCD567890EF",
        "X-Apple-I-MD" to "an-otp",
        "X-Apple-I-MD-M" to "a-machine-id",
        "X-Apple-I-MLB" to "C02X12345678",
        "X-Apple-I-ROM" to "aabbccddeeff",
        "X-Apple-I-SRL-NO" to "C02X1Y2ZLVDL",
    )
    private val keychainIdentifier = ByteArray(16) { (it + 1).toByte() }

    private fun cpd(apnsToken: String? = null, flavor: GsaFlavor = GsaFlavor.MESSAGES) = GsaCpd(
        anisette = anisette,
        keychainIdentifier = keychainIdentifier,
        flavor = flavor,
        apnsToken = apnsToken,
    )

    private fun dict(apnsToken: String? = null) = cpd(apnsToken).dictFor("A1B2C3D4-E5F6-4789-ABCD-0123456789AB")

    @Test
    fun `the anisette values ride as keys, hardware headers excluded`() {
        val dict = dict()
        assertEquals("2026-09-11T12:00:00Z", dict["X-Apple-I-Client-Time"])
        assertEquals("an-otp", dict["X-Apple-I-MD"])
        assertEquals("a-machine-id", dict["X-Apple-I-MD-M"])
        assertEquals("17106176", dict["X-Apple-I-MD-RINFO"])
        assertEquals("1234ABCD-5678-90EF-1234-ABCD567890EF", dict["X-Mme-Device-Id"])
        // §1.5 cpd keys are the per-request anisette set; the §1.1 hardware headers are not in it.
        assertNull(dict["X-Apple-I-MLB"])
        assertNull(dict["X-Apple-I-ROM"])
        assertNull(dict["X-Apple-I-SRL-NO"])
        assertNull(dict["X-Apple-I-TimeZone"])
        assertNull(dict["X-Apple-Locale"])
    }

    @Test
    fun `md-lu is lowercase hex sha-256 of the keychain identifier`() {
        val expected = MessageDigest.getInstance("SHA-256").digest(keychainIdentifier)
            .joinToString("") { "%02x".format(it) }
        assertEquals(expected, dict()["X-Apple-I-MD-LU"])
    }

    @Test
    fun `recorded fixed values are pinned`() {
        val dict = dict()
        assertEquals("0", dict["X-Apple-I-Device-Configuration-Mode"])
        assertEquals("A1B2C3D4-E5F6-4789-ABCD-0123456789AB", dict["X-Apple-I-Request-UUID"])
        assertEquals("0", dict["X-Apple-Requested-Partition"])
        assertEquals("com.apple.authkit.generic", dict["X-Apple-Security-Upgrade-Context"])
        assertEquals("US", dict["cou"])
        assertEquals("en_US", dict["loc"])
    }

    @Test
    fun `the recorded per-flavor capp cbid svct values`() {
        val messages = dict()["capp"]
        assertEquals("Messages", messages)
        assertEquals("com.apple.MobileSMS", dict()["cbid"])
        assertEquals("imessage", dict()["svct"])

        val icloud = cpd(flavor = GsaFlavor.APPLE_ID_SETTINGS).dictFor("A1B2C3D4-E5F6-4789-ABCD-0123456789AB")
        assertEquals("icloud", icloud["capp"])
        assertEquals("com.apple.systempreferences.AppleIDSettings", icloud["cbid"])
        assertEquals("icloud", icloud["svct"])
    }

    @Test
    fun `recorded booleans are pinned`() {
        val dict = dict()
        assertEquals(true, dict["X-Apple-Offer-Security-Upgrade"])
        assertEquals(false, dict["at"])
        assertEquals(true, dict["bootstrap"])
        assertEquals(true, dict["ckgen"])
        assertEquals(true, dict["fcd"])
        assertEquals(false, dict["icdrsDisabled"])
        assertEquals(true, dict["icscrec"])
        assertEquals(false, dict["pbe"])
        assertEquals(true, dict["prkgen"])
        assertEquals(false, dict["webAccessEnabled"])
    }

    @Test
    fun `ptkn is optional`() {
        assertNull(dict()["ptkn"])
        assertEquals("apns-token", dict(apnsToken = "apns-token")["ptkn"])
    }

    @Test
    fun `the filtered anisette header set rides the POSTs with the derived md-lu`() {
        val headers = cpd().headersFor()
        assertEquals("an-otp", headers["X-Apple-I-MD"])
        assertEquals("a-machine-id", headers["X-Apple-I-MD-M"])
        assertEquals("17106176", headers["X-Apple-I-MD-RINFO"])
        assertEquals("1234ABCD-5678-90EF-1234-ABCD567890EF", headers["X-Mme-Device-Id"])
        assertEquals(dict()["X-Apple-I-MD-LU"], headers["X-Apple-I-MD-LU"])
        // The filtered set: client-time is a cpd key only, hardware headers appear on neither.
        assertNull(headers["X-Apple-I-Client-Time"])
        assertNull(headers["X-Apple-I-MLB"])
    }

    @Test
    fun `akd-variant headers carry the recorded values`() {
        val headers = GsaHeaderConfig(
            flavor = GsaFlavor.MESSAGES,
            hardwareModel = "iMac13,1",
            osName = "macOS",
            osVersion = "13.6.4",
            osBuild = "22G513",
        ).toHeaders()
        assertEquals(
            mapOf(
                "X-MMe-Client-Info" to "<iMac13,1> <macOS;13.6.4;22G513> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
                "User-Agent" to "akd/1.0 CFNetwork/1494.0.7 Darwin/23.4.0",
                "X-Apple-AK-Context-Type" to "imessage",
                "X-Apple-Client-App-Name" to "Messages",
                "X-Apple-I-Client-Bundle-Id" to "com.apple.MobileSMS",
            ),
            headers,
        )
        val icloud = GsaHeaderConfig(
            flavor = GsaFlavor.APPLE_ID_SETTINGS,
            hardwareModel = "iPhone7,2",
            osName = "iPhone OS",
            osVersion = "12.5.5",
            osBuild = "16H62",
        ).toHeaders()
        assertEquals("icloud", icloud["X-Apple-AK-Context-Type"])
        assertEquals("icloud", icloud["X-Apple-Client-App-Name"])
        assertEquals("com.apple.systempreferences.AppleIDSettings", icloud["X-Apple-I-Client-Bundle-Id"])
    }

    @Test
    fun `the full key set is exactly the recorded one`() {
        val expected = setOf(
            "X-Apple-I-Client-Time",
            "X-Apple-I-MD",
            "X-Apple-I-MD-LU",
            "X-Apple-I-MD-M",
            "X-Apple-I-MD-RINFO",
            "X-Mme-Device-Id",
            "X-Apple-I-Device-Configuration-Mode",
            "X-Apple-I-Request-UUID",
            "X-Apple-Requested-Partition",
            "X-Apple-Security-Upgrade-Context",
            "capp",
            "cbid",
            "cou",
            "loc",
            "svct",
            "X-Apple-Offer-Security-Upgrade",
            "at",
            "bootstrap",
            "ckgen",
            "fcd",
            "icdrsDisabled",
            "icscrec",
            "pbe",
            "prkgen",
            "webAccessEnabled",
        )
        assertTrue(dict().keys == expected, "cpd keys ${dict().keys} != the §1.5 recorded set")
    }
}
