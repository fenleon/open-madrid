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
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The §1.1 Mac-Hardware-Info export-code parser (C58). Fixtures are hand-built with a
 * test-local protobuf encoder over the recorded field map; the restricted mode is encrypted
 * test-side with an independent EVP_BytesToKey implementation.
 */
class MacHardwareInfoExportTest {

    @Test
    fun `parses the raw payload bytes with every recorded field`() {
        val export = MacHardwareInfoExportCode.parsePayload(FULL_PAYLOAD(flag = 0))

        assertTrue(!export.preventSharing)
        assertEquals("13.4", export.macOsProductVersion)
        assertEquals(1640L, export.protocolVersion)
        assertEquals("DEVICE-UUID", export.deviceId)
        assertEquals("iCloudHelper/282 (test)", export.icloudHelperUserAgent)
        assertEquals("AOSKit/282 (test)", export.aosKitVersion)

        val id = export.identifiers
        assertEquals("MacBookPro18,3", id.productName)
        assertEquals(MAC_ADDRESS.toList(), id.macAddress!!.toList())
        assertEquals("C02SERIALVALUE", id.serialNumber)
        assertEquals("PLATFORM-UUID", id.platformUuid)
        assertEquals("ROOT-DISK-UUID", id.rootDiskUuid)
        assertEquals("Mac-BBAA2211FFEE0011", id.boardId)
        assertEquals("21G217", id.osBuildNumber)
        assertEquals(listOf<Byte>(1, 2, 3), id.serialEnc!!.toList())
        assertEquals(listOf<Byte>(4, 5), id.platformUuidEnc!!.toList())
        assertEquals(listOf<Byte>(6), id.rootDiskUuidEnc!!.toList())
        assertEquals(ROM.toList(), id.rom.toList())
        assertEquals(listOf<Byte>(7, 8, 9, 10), id.romEnc!!.toList())
        assertEquals("MLB-STRING-VALUE", id.logicBoardSerial)
        assertEquals(listOf<Byte>(11, 12), id.mlbEnc!!.toList())
    }

    @Test
    fun `parses plain base64 text`() {
        val export = MacHardwareInfoExportCode.parse(
            Base64.getEncoder().encodeToString(FULL_PAYLOAD(flag = 0)),
        )
        assertEquals("C02SERIALVALUE", export.identifiers.serialNumber)
    }

    @Test
    fun `the flag byte selects prevent-sharing mode`() {
        assertTrue(MacHardwareInfoExportCode.parsePayload(FULL_PAYLOAD(flag = 1)).preventSharing)
        assertTrue(!MacHardwareInfoExportCode.parsePayload(FULL_PAYLOAD(flag = 0)).preventSharing)
    }

    @Test
    fun `unknown fields are skipped`() {
        val identifiers = TestProto.message(
            TestProto.stringField(1, "MacBookPro18,3"),
            TestProto.bytesField(2, MAC_ADDRESS),
            TestProto.stringField(3, "C02SERIALVALUE"),
            TestProto.stringField(13, "MLB-STRING-VALUE"),
            TestProto.bytesField(11, ROM),
            TestProto.varintField(20, 12345L), // unknown
            TestProto.bytesField(21, byteArrayOf(9, 9)), // unknown
        )
        val outer = TestProto.message(
            TestProto.bytesField(1, identifiers),
            TestProto.varintField(15, 7L), // unknown varint
            TestProto.bytesField(16, "unknown".toByteArray()), // unknown length-delimited
        )
        val export = MacHardwareInfoExportCode.parsePayload("OABS".toByteArray() + byteArrayOf(0) + outer)
        assertEquals("C02SERIALVALUE", export.identifiers.serialNumber)
        assertNull(export.macOsProductVersion)
    }

    @Test
    fun `wrong magic fails loudly`() {
        val payload = "XABS".toByteArray() + byteArrayOf(0) + TestProto.message()
        val exception = assertFailsWith<MacHardwareInfoExportException> {
            MacHardwareInfoExportCode.parsePayload(payload)
        }
        assertTrue(exception.message!!.contains("magic"))
        assertFailsWith<MacHardwareInfoExportException> {
            MacHardwareInfoExportCode.parse(Base64.getEncoder().encodeToString(payload))
        }
    }

    @Test
    fun `truncated payload, missing identifier message, and bad flag fail loudly`() {
        assertFailsWith<MacHardwareInfoExportException> { MacHardwareInfoExportCode.parsePayload("OA".toByteArray()) }
        assertFailsWith<MacHardwareInfoExportException> {
            MacHardwareInfoExportCode.parsePayload("OABS".toByteArray() + byteArrayOf(0))
        }
        val noIdentifiers = TestProto.message(TestProto.stringField(2, "13.4"))
        assertFailsWith<MacHardwareInfoExportException> {
            MacHardwareInfoExportCode.parsePayload("OABS".toByteArray() + byteArrayOf(0) + noIdentifiers)
        }
        assertFailsWith<MacHardwareInfoExportException> {
            MacHardwareInfoExportCode.parsePayload("OABS".toByteArray() + byteArrayOf(2) + noIdentifiers)
        }
    }

    @Test
    fun `identifier message without the required fields fails loudly`() {
        val identifiers = TestProto.message(TestProto.stringField(1, "MacBookPro18,3"))
        val outer = TestProto.message(TestProto.bytesField(1, identifiers))
        assertFailsWith<MacHardwareInfoExportException> {
            MacHardwareInfoExportCode.parsePayload("OABS".toByteArray() + byteArrayOf(0) + outer)
        }
    }

    @Test
    fun `the hardcoded protocol version is the recorded 1640`() {
        assertEquals(1640L, MacHardwareInfoExportCode.PROTOCOL_VERSION)
    }

    @Test
    fun `restricted mode decrypts with the activation code and parses`() {
        val code = "MBABCDEFGH23456789ABCDEFGH234567"
        val container = restrictedContainer(FULL_PAYLOAD(flag = 1), code)

        val export = MacHardwareInfoExportCode.parse(
            Base64.getEncoder().encodeToString(container),
            activationCode = code,
        )
        assertTrue(export.preventSharing)
        assertEquals("C02SERIALVALUE", export.identifiers.serialNumber)
        assertEquals("MLB-STRING-VALUE", export.identifiers.logicBoardSerial)
    }

    @Test
    fun `restricted mode without or with the wrong activation code fails loudly`() {
        val code = "MBABCDEFGH23456789ABCDEFGH234567"
        val container = Base64.getEncoder().encodeToString(restrictedContainer(FULL_PAYLOAD(flag = 0), code))
        assertFailsWith<MacHardwareInfoExportException> { MacHardwareInfoExportCode.parse(container) }
        val exception = assertFailsWith<MacHardwareInfoExportException> {
            MacHardwareInfoExportCode.parse(container, activationCode = "MBZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")
        }
        assertTrue(exception.message!!.contains("activation code"))
    }

    @Test
    fun `plain text without a container prefix ignores the activation code`() {
        val export = MacHardwareInfoExportCode.parse(
            Base64.getEncoder().encodeToString(FULL_PAYLOAD(flag = 0)),
            activationCode = "not-a-code-for-plain-mode",
        )
        assertEquals("C02SERIALVALUE", export.identifiers.serialNumber)
    }

    @Test
    fun `parsed identifiers feed the anisette hardware headers`() {
        val export = MacHardwareInfoExportCode.parsePayload(FULL_PAYLOAD(flag = 0))
        val headers = AnisetteHeaderProvider(
            machineId,
            export.identifiers,
            AnisetteOtpTestDouble("otp-bytes".toByteArray()),
            AnisetteValueFormats({ "t-$it" }, "UTC", "en_US", "17106176", "device-id"),
        ).headers(nowEpochMs = 1_000L, oneTimeIdentifier = byteArrayOf(9))

        assertEquals("C02SERIALVALUE", headers["X-Apple-I-SRL-NO"])
        assertEquals("MLB-STRING-VALUE", headers["X-Apple-I-MLB"])
        assertEquals(ROM.joinToString("") { "%02x".format(it) }, headers["X-Apple-I-ROM"])
    }

    // ---- hand-built protobuf encoder + restricted-mode encryptor (test-side only) ----

    /** Minimal protobuf wire writer for the fixtures (main side only decodes). */
    private object TestProto {
        fun varint(value: Long): ByteArray {
            var v = value
            val out = ArrayList<Byte>()
            while (true) {
                if (v and 0x7f.inv() == 0L) {
                    out.add(v.toByte())
                    return out.toByteArray()
                }
                out.add(((v and 0x7f) or 0x80).toByte())
                v = v ushr 7
            }
        }

        fun message(vararg fields: ByteArray): ByteArray {
            val size = fields.sumOf { it.size }
            return ByteArray(size).also { buffer ->
                var at = 0
                fields.forEach { it.copyInto(buffer, at); at += it.size }
            }
        }

        private fun tag(number: Int, wireType: Int): ByteArray = varint((number.toLong() shl 3) or wireType.toLong())

        fun stringField(number: Int, value: String): ByteArray =
            lenDelimited(number, value.toByteArray(Charsets.UTF_8))

        fun bytesField(number: Int, value: ByteArray): ByteArray = lenDelimited(number, value)

        fun varintField(number: Int, value: Long): ByteArray = tag(number, 0) + varint(value)

        private fun lenDelimited(number: Int, payload: ByteArray): ByteArray =
            tag(number, 2) + varint(payload.size.toLong()) + payload
    }

    /** Independent EVP_BytesToKey (§1.1): repeated MD5 of prev ‖ password ‖ salt → 32-byte key + 16-byte IV. */
    private fun evpKeyIv(password: ByteArray, salt: ByteArray): Pair<ByteArray, ByteArray> {
        val md5 = MessageDigest.getInstance("MD5")
        var prev = ByteArray(0)
        val derived = ByteArray(48)
        var at = 0
        while (at < 48) {
            prev = md5.digest(prev + password + salt)
            val chunk = minOf(prev.size, 48 - at)
            System.arraycopy(prev, 0, derived, at, chunk)
            at += chunk
        }
        return derived.copyOfRange(0, 32) to derived.copyOfRange(32, 48)
    }

    /** Builds the §1.1 restricted container: `Salted__` ‖ 8-byte salt ‖ AES-256-CBC/PKCS7 payload. */
    private fun restrictedContainer(payload: ByteArray, activationCode: String): ByteArray {
        val salt = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        val (key, iv) = evpKeyIv(activationCode.toByteArray(Charsets.UTF_8), salt)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return "Salted__".toByteArray(Charsets.US_ASCII) + salt + cipher.doFinal(payload)
    }

    companion object {
        private val MAC_ADDRESS = byteArrayOf(0xA1.toByte(), 0xB2.toByte(), 0xC3.toByte(), 0x01, 0x02, 0x03)
        private val ROM = byteArrayOf(0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F)
        private val machineId = byteArrayOf(1, 2, 3, 4)

        private fun identifierMessage() = TestProto.message(
            TestProto.stringField(1, "MacBookPro18,3"),
            TestProto.bytesField(2, MAC_ADDRESS),
            TestProto.stringField(3, "C02SERIALVALUE"),
            TestProto.stringField(4, "PLATFORM-UUID"),
            TestProto.stringField(5, "ROOT-DISK-UUID"),
            TestProto.stringField(6, "Mac-BBAA2211FFEE0011"),
            TestProto.stringField(7, "21G217"),
            TestProto.bytesField(8, byteArrayOf(1, 2, 3)),
            TestProto.bytesField(9, byteArrayOf(4, 5)),
            TestProto.bytesField(10, byteArrayOf(6)),
            TestProto.bytesField(11, ROM),
            TestProto.bytesField(12, byteArrayOf(7, 8, 9, 10)),
            TestProto.stringField(13, "MLB-STRING-VALUE"),
            TestProto.bytesField(14, byteArrayOf(11, 12)),
        )

        private fun FULL_PAYLOAD(flag: Int): ByteArray {
            val outer = TestProto.message(
                TestProto.bytesField(1, identifierMessage()),
                TestProto.stringField(2, "13.4"),
                TestProto.varintField(3, 1640L),
                TestProto.stringField(4, "DEVICE-UUID"),
                TestProto.stringField(5, "iCloudHelper/282 (test)"),
                TestProto.stringField(6, "AOSKit/282 (test)"),
            )
            return "OABS".toByteArray(Charsets.US_ASCII) + byteArrayOf(flag.toByte()) + outer
        }
    }
}
