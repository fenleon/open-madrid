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
import dev.fenn.imessage.crypto.Hkdf
import dev.fenn.imessage.ids.IdsSigning
import dev.fenn.imessage.ids.TunnelReply
import dev.fenn.imessage.ids.TunnelStatus
import dev.fenn.imessage.crypto.EcCrypto
import dev.fenn.imessage.crypto.MessageBody
import dev.fenn.imessage.crypto.PairEcEnvelope
import dev.fenn.imessage.crypto.PairEnvelope
import dev.fenn.imessage.crypto.PayloadCommands
import java.security.PrivateKey
import java.security.Signature
import javax.crypto.KeyAgreement
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The §1.1 step-3 context. Two assertion kinds, named per the task split:
 *
 * - **Spec-pinned**: the hardware-configuration consumption (field set, the five `_enc`
 *   blobs' label mapping and verbatim pass-through) and the recorded contract shape
 *   (create → establish → sign order, all state in the context).
 * - **Reconstruction-shape**: everything the framing/KDF/signature strategies decide — these
 *   assertions pin the hypothesis's structure and plumbing, NOT Apple's protocol. The live
 *   server is the arbiter (C5/C6 remaining).
 */
class ValidationDataGeneratorTest {

    private val certificate = byteArrayOf(1, 2, 3, 4)

    private val hardware = HardwareConfiguration.from(
        productName = "Macmini9,1",
        macAddress = byteArrayOf(1, 2, 3, 4, 5, 6),
        platformSerial = "C02SERIAL",
        platformUuid = "PLATFORM-UUID",
        rootDiskUuid = "ROOT-DISK-UUID",
        boardId = "Mac-AAAA",
        osBuildNumber = "22G513",
        rom = byteArrayOf(9, 8, 7),
        mlb = "MLB-STRING",
        serialEnc = byteArrayOf(10),
        platformUuidEnc = byteArrayOf(11),
        rootDiskUuidEnc = byteArrayOf(12),
        romEnc = byteArrayOf(13),
        mlbEnc = byteArrayOf(14),
    )

    private fun generator(
        strategies: ValidationDataStrategies = ValidationDataStrategies(),
    ) = ValidationDataGenerator(
        certificateChain = listOf(certificate),
        hardware = hardware,
        strategies = strategies,
        random = java.security.SecureRandom(),
    )

    private fun fieldsOf(blob: ByteArray) = ValidationDataFraming.parse(blob)

    private fun fieldValue(blob: ByteArray, tag: Int): ByteArray =
        fieldsOf(blob).first { it.tag == tag }.value

    // ---- spec-pinned: the hardware-configuration consumption ----

    @Test
    fun `hardware configuration consumes the recorded field set from the export identifiers`() {
        val config = HardwareConfiguration.from(
            MacHardwareIdentifiers(
                serialNumber = "C02SERIAL",
                logicBoardSerial = "MLB-STRING",
                rom = byteArrayOf(9, 8, 7),
                productName = "Macmini9,1",
                macAddress = byteArrayOf(1, 2, 3, 4, 5, 6),
                platformUuid = "PLATFORM-UUID",
                rootDiskUuid = "ROOT-DISK-UUID",
                boardId = "Mac-AAAA",
                osBuildNumber = "22G513",
                serialEnc = byteArrayOf(10),
                platformUuidEnc = byteArrayOf(11),
                rootDiskUuidEnc = byteArrayOf(12),
                romEnc = byteArrayOf(13),
                mlbEnc = byteArrayOf(14),
            ),
        )
        assertEquals("Macmini9,1", config.productName)
        assertEquals("22G513", config.osBuildNumber)
        assertEquals("C02SERIAL", config.platformSerial)
        assertEquals("PLATFORM-UUID", config.platformUuid)
        assertEquals("ROOT-DISK-UUID", config.rootDiskUuid)
        assertEquals("Mac-AAAA", config.boardId)
        assertEquals("MLB-STRING", config.mlb)
        assertEquals(byteArrayOf(1, 2, 3, 4, 5, 6).toList(), config.macAddress.toList())
        assertEquals(byteArrayOf(9, 8, 7).toList(), config.rom.toList())
    }

    @Test
    fun `the five _enc blobs pass through under the recorded label mapping`() {
        val labels = HardwareConfiguration.EncLabel
        assertEquals(
            mapOf(
                labels.SERIAL to byteArrayOf(10).toList(),
                labels.PLATFORM_UUID to byteArrayOf(11).toList(),
                labels.ROOT_DISK_UUID to byteArrayOf(12).toList(),
                labels.ROM to byteArrayOf(13).toList(),
                labels.MLB to byteArrayOf(14).toList(),
            ),
            hardware.encVariants.mapValues { it.value.toList() },
        )
    }

    @Test
    fun `missing _enc variants or a malformed mac address fail loudly`() {
        val identifiers = MacHardwareIdentifiers(
            serialNumber = "S",
            logicBoardSerial = "M",
            rom = byteArrayOf(1),
            productName = "Macmini9,1",
            macAddress = byteArrayOf(1, 2, 3, 4, 5, 6),
            platformUuid = "PU",
            rootDiskUuid = "RU",
            boardId = "Mac-AAAA",
            osBuildNumber = "22G513",
            serialEnc = byteArrayOf(10),
            platformUuidEnc = byteArrayOf(11),
            rootDiskUuidEnc = byteArrayOf(12),
            romEnc = byteArrayOf(13),
            mlbEnc = null, // §1.1 requires all five _enc variants — C57 derivation, C58 delivery
        )
        assertFailsWith<ValidationDataException> { HardwareConfiguration.from(identifiers) }

        // §1.1: exactly 6 raw MAC bytes.
        assertFailsWith<ValidationDataException> {
            HardwareConfiguration.from(
                productName = "Macmini9,1",
                macAddress = byteArrayOf(1, 2, 3),
                platformSerial = "C02SERIAL",
                platformUuid = "PLATFORM-UUID",
                rootDiskUuid = "ROOT-DISK-UUID",
                boardId = "Mac-AAAA",
                osBuildNumber = "22G513",
                rom = byteArrayOf(9),
                mlb = "MLB-STRING",
                serialEnc = byteArrayOf(10),
                platformUuidEnc = byteArrayOf(11),
                rootDiskUuidEnc = byteArrayOf(12),
                romEnc = byteArrayOf(13),
                mlbEnc = byteArrayOf(14),
            )
        }
    }

    // ---- reconstruction-shape: the contract order and the framing/KDF/signature plumbing ----

    @Test
    fun `session-info-request frames the chain, the hardware configuration and the context public keys`() {
        val request = generator().createSessionInfoRequest()
        val tags = fieldsOf(request).map { it.tag }
        // Reconstruction shape (TLV_V1): every §1.1 hardware field, the step-1 cert, both pubs.
        assertEquals(
            listOf(
                ValidationDataFields.PRODUCT_NAME,
                ValidationDataFields.OS_BUILD_NUMBER,
                ValidationDataFields.PLATFORM_SERIAL,
                ValidationDataFields.PLATFORM_UUID,
                ValidationDataFields.ROOT_DISK_UUID,
                ValidationDataFields.BOARD_ID,
                ValidationDataFields.MAC_ADDRESS,
                ValidationDataFields.ROM,
                ValidationDataFields.MLB,
                ValidationDataFields.SERIAL_ENC,
                ValidationDataFields.PLATFORM_UUID_ENC,
                ValidationDataFields.ROOT_DISK_UUID_ENC,
                ValidationDataFields.ROM_ENC,
                ValidationDataFields.MLB_ENC,
                ValidationDataFields.CERTIFICATE,
                ValidationDataFields.KA_PUBLIC_KEY,
                ValidationDataFields.SIGNING_PUBLIC_KEY,
            ),
            tags,
        )
        assertEquals(certificate.toList(), fieldValue(request, ValidationDataFields.CERTIFICATE).toList())
        assertEquals(33, fieldValue(request, ValidationDataFields.KA_PUBLIC_KEY).size)
        assertEquals(33, fieldValue(request, ValidationDataFields.SIGNING_PUBLIC_KEY).size)
    }

    @Test
    fun `the key-agreement keypair is fresh per context`() {
        val first = fieldValue(generator().createSessionInfoRequest(), ValidationDataFields.KA_PUBLIC_KEY)
        val second = fieldValue(generator().createSessionInfoRequest(), ValidationDataFields.KA_PUBLIC_KEY)
        assertTrue(!first.contentEquals(second))
    }

    @Test
    fun `sign before establishKeys fails loudly`() {
        assertFailsWith<ValidationDataException> { generator().sign() }
    }

    @Test
    fun `hmac strategy - sign frames the context fields plus a session-key mac over them`() {
        val server = EcKeys.p256(java.security.SecureRandom())
        val context = generator(
            ValidationDataStrategies(signature = ValidationDataStrategies.BlobSignature.HMAC_SHA256),
        )
        val request = context.createSessionInfoRequest()
        context.establishKeys(EcCrypto.compress(server.public))

        val blob = context.sign()
        val fields = fieldsOf(blob)
        val signatureField = fields.last()
        val body = ValidationDataFraming.frame(fields.dropLast(1))

        // The blob = the framed fields (same field list as the request) + the SIGNATURE field.
        assertEquals(ValidationDataFields.SIGNATURE, signatureField.tag)
        assertEquals(
            fieldsOf(request).map { it.tag to it.value.toList() },
            fields.dropLast(1).map { it.tag to it.value.toList() },
        )
        // The MAC verifies against the session key the SERVER-side agreement derives.
        val serverShared = agree("ECDH", server.private, EcCrypto.decompress(
            fieldValue(request, ValidationDataFields.KA_PUBLIC_KEY),
        ))
        val serverSessionKey = Hkdf.expand(
            Hkdf.extract(ByteArray(0), serverShared), ByteArray(0), 32,
        )
        assertTrue(Hkdf.hmac(serverSessionKey, body).contentEquals(signatureField.value))
    }

    @Test
    fun `ecdsa strategy - the signature verifies against the context signing public key`() {
        val server = EcKeys.p256(java.security.SecureRandom())
        val context = generator(
            ValidationDataStrategies(
                signature = ValidationDataStrategies.BlobSignature.ECDSA_P256_SHA256,
            ),
        )
        val request = context.createSessionInfoRequest()
        context.establishKeys(EcCrypto.compress(server.public))
        val blob = context.sign()

        val fields = fieldsOf(blob)
        assertEquals(ValidationDataFields.SIGNATURE, fields.last().tag)
        val body = ValidationDataFraming.frame(fields.dropLast(1))
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(EcCrypto.decompress(fieldValue(request, ValidationDataFields.SIGNING_PUBLIC_KEY)))
        verifier.update(body)
        assertTrue(verifier.verify(fields.last().value))
    }

    @Test
    fun `x25519 scheme is plumbed end to end`() {
        val server = EcKeys.x25519(java.security.SecureRandom())
        val context = generator(
            ValidationDataStrategies(keyAgreement = ValidationDataStrategies.KeyAgreementScheme.X25519),
        )
        val request = context.createSessionInfoRequest()
        assertEquals(32, fieldValue(request, ValidationDataFields.KA_PUBLIC_KEY).size)
        context.establishKeys(EcKeys.x25519Raw(server.public))
        val blob = context.sign()
        assertEquals(ValidationDataFields.SIGNATURE, fieldsOf(blob).last().tag)
    }

    @Test
    fun `an unparsable session-info fails loudly under the raw-public-point strategy`() {
        val context = generator()
        assertFailsWith<ValidationDataException> { context.establishKeys(byteArrayOf(1, 2, 3)) }
    }

    @Test
    fun `a 65-byte uncompressed server point is accepted as session-info`() {
        val server = EcKeys.p256(java.security.SecureRandom())
        val context = generator()
        context.establishKeys(uncompressed(server.public))
        context.sign()
    }

    private fun uncompressed(public: java.security.PublicKey): ByteArray {
        val w = (public as java.security.interfaces.ECPublicKey).w
        val out = ByteArray(65)
        out[0] = 0x04
        fixed32(w.affineX).copyInto(out, 1)
        fixed32(w.affineY).copyInto(out, 33)
        return out
    }

    private fun fixed32(v: java.math.BigInteger): ByteArray {
        val raw = v.toByteArray()
        val out = ByteArray(32)
        raw.copyInto(out, maxOf(0, 32 - raw.size), maxOf(0, raw.size - 32))
        return out
    }

    private fun agree(algorithm: String, privateKey: PrivateKey, public: java.security.PublicKey): ByteArray {
        val agreement = KeyAgreement.getInstance(algorithm)
        agreement.init(privateKey)
        agreement.doPhase(public, true)
        return agreement.generateSecret()
    }
}
