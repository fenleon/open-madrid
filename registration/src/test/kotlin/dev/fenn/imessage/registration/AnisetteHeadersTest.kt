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
import kotlin.test.assertTrue

/**
 * The recorded §1.1 header set is pinned by name and by recorded value form (base64 OTP,
 * base64 machine ID, lowercase-hex ROM). Everything the spec leaves unrecorded — client-time
 * format, timezone/locale/rinfo/device-id values, the OTP derivation, the one-time identifier
 * — flows through caller-supplied seams and is tested structurally only.
 */
class AnisetteHeadersTest {

    private val machineId = byteArrayOf(1, 2, 3, 4)
    private val rom = byteArrayOf(0xAB.toByte(), 0x0C, 0x7F)

    private fun formats() = AnisetteValueFormats(
        clientTime = { ms -> "formatted-$ms" },
        timeZone = "America/Los_Angeles",
        locale = "en_US",
        rinfo = "17106197",
        deviceId = "device-id-value",
    )

    private fun otpRecording(output: ByteArray = "otp-bytes".toByteArray()) =
        AnisetteOtpTestDouble(output)

    private fun provider(
        otp: AnisetteOtp = otpRecording(),
        macHardware: MacHardwareIdentifiers? = MacHardwareIdentifiers("SERIAL123", "MLB-VALUE", rom),
    ) = AnisetteHeaderProvider(machineId, macHardware, otp, formats())

    @Test
    fun `full header set carries exactly the recorded names in mac hardware mode`() {
        val headers = provider().headers(nowEpochMs = 1_000L, oneTimeIdentifier = byteArrayOf(9))

        assertEquals(
            listOf(
                "X-Apple-I-Client-Time",
                "X-Apple-I-TimeZone",
                "X-Apple-Locale",
                "X-Apple-I-MD-RINFO",
                "X-Mme-Device-Id",
                "X-Apple-I-MD",
                "X-Apple-I-MD-M",
                "X-Apple-I-MLB",
                "X-Apple-I-ROM",
                "X-Apple-I-SRL-NO",
            ),
            headers.keys.toList(),
        )
    }

    @Test
    fun `hardware headers are omitted without mac identifiers`() {
        val headers = provider(macHardware = null).headers(1_000L, byteArrayOf(9))

        assertEquals(7, headers.size)
        assertTrue(headers.keys.none { it.startsWith("X-Apple-I-MLB") || it == "X-Apple-I-ROM" || it == "X-Apple-I-SRL-NO" })
    }

    @Test
    fun `recorded value forms - base64 otp and machine id, lowercase hex rom`() {
        val headers = provider().headers(1_000L, byteArrayOf(9))

        assertEquals(Base64.getEncoder().encodeToString("otp-bytes".toByteArray()), headers["X-Apple-I-MD"])
        assertEquals(Base64.getEncoder().encodeToString(machineId), headers["X-Apple-I-MD-M"])
        assertEquals("ab0c7f", headers["X-Apple-I-ROM"])
        assertEquals("MLB-VALUE", headers["X-Apple-I-MLB"])
        assertEquals("SERIAL123", headers["X-Apple-I-SRL-NO"])
    }

    @Test
    fun `capture-bound values flow through the caller-supplied formats`() {
        val headers = provider().headers(nowEpochMs = 1_234_567L, oneTimeIdentifier = byteArrayOf(9))

        assertEquals("formatted-1234567", headers["X-Apple-I-Client-Time"])
        assertEquals("America/Los_Angeles", headers["X-Apple-I-TimeZone"])
        assertEquals("en_US", headers["X-Apple-Locale"])
        assertEquals("17106197", headers["X-Apple-I-MD-RINFO"])
        assertEquals("device-id-value", headers["X-Mme-Device-Id"])
    }

    @Test
    fun `otp seam receives machine state and the one-time identifier verbatim`() {
        val otp = otpRecording()
        val oneTime = byteArrayOf(0x55, 0x66)

        provider(otp = otp).headers(1_000L, oneTime)

        assertEquals(1, otp.inputs.size)
        assertTrue(otp.inputs[0].machineIdentifier.contentEquals(machineId))
        assertTrue(otp.inputs[0].oneTimeIdentifier.contentEquals(oneTime))
    }

    @Test
    fun `empty otp output fails loudly`() {
        val exception = assertFailsWith<AnisetteException> {
            provider(otp = otpRecording(ByteArray(0))).headers(1_000L, byteArrayOf(9))
        }
        assertEquals("OTP seam returned no bytes for X-Apple-I-MD", exception.message)
    }
}

/** OTP test double: records every input, returns a fixed output. */
class AnisetteOtpTestDouble(private val output: ByteArray) : AnisetteOtp {
    val inputs = mutableListOf<AnisetteOtpInput>()

    override fun otp(input: AnisetteOtpInput): ByteArray {
        inputs.add(input)
        return output
    }
}
