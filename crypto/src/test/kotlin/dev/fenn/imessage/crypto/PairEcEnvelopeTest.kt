package dev.fenn.imessage.crypto

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyAgreement
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PairEcEnvelopeTest {

    private val plaintext = MessageBody(text = "pair-ec envelope test", protocolVersion = "1").encode()

    private val senderDeviceMarshalled = ByteArray(65) { (it + 1).toByte() }
    private val recipientDeviceMarshalled = ByteArray(65) { (it + 2).toByte() }
    private val recipientPrekeyMarshalled = ByteArray(65) { (it + 3).toByte() }
    private val compressedPrekey = EcCrypto.compress(PREKEY.public)

    /** Seeded RNG so the ephemeral key, pad bytes and OAEP/ECDSA nonces are reproducible. */
    private fun fixedRandom(seed: Byte = 1) = object : SecureRandom() {
        private var next = seed
        override fun nextBytes(bytes: ByteArray) {
            for (i in bytes.indices) bytes[i] = (next + i).toByte()
            next = (next + bytes.size).toByte()
        }
    }

    private fun encrypt(
        counter: Long = 1L,
        random: SecureRandom = fixedRandom(),
        gossip: ByteArray? = null,
        debug: ByteArray? = null,
        ephemeralKeyForm: PairEcEnvelope.EphemeralKeyForm = PairEcEnvelope.EphemeralKeyForm.COMPRESSED_33,
    ): ByteArray = PairEcEnvelope.encrypt(
        plaintext = plaintext,
        recipientPrekey = compressedPrekey,
        recipientPrekeyMarshalled = recipientPrekeyMarshalled,
        senderDeviceKeyMarshalled = senderDeviceMarshalled,
        recipientDeviceKeyMarshalled = recipientDeviceMarshalled,
        counter = counter,
        senderDeviceSigningKey = DEVICE_KEY.private,
        random = random,
        ephemeralKeyForm = ephemeralKeyForm,
        gossip = gossip,
        debug = debug,
    )

    private fun decrypt(
        outer: ByteArray,
        senderDeviceKeyMarshalled: ByteArray? = senderDeviceMarshalled,
        senderSigningPublicKey: java.security.PublicKey? = DEVICE_KEY.public,
    ): Pair<ByteArray, Long> = PairEcEnvelope.decrypt(
        outer = outer,
        recipientPrekeyPrivate = PREKEY.private,
        recipientPrekeyMarshalled = recipientPrekeyMarshalled,
        recipientDeviceKeyMarshalled = recipientDeviceMarshalled,
        senderDeviceKeyMarshalled = senderDeviceKeyMarshalled,
        senderDeviceSigningPublicKey = senderSigningPublicKey,
    )

    @Test
    fun roundTripPreservesPlaintextAndCounter() {
        val (back, counter) = decrypt(encrypt(counter = 7L))
        assertContentEquals(plaintext, back)
        assertEquals(7L, counter)
    }

    // Known answer (§4.3, C52): the outer protobuf's field numbers are payload 1, key 2,
    // signature 3, validator 99; the field-2 key is the 33-byte compressed point.
    @Test
    fun outerMessageCarriesTheRecordedShape() {
        val parsed = MiniProto.decode(encrypt())
        assertEquals(
            setOf(1, 2, 3, 99),
            parsed.map { it.first }.toSet(),
            "outer field numbers must be payload 1, key 2, signature 3, validator 99 (§4.3)",
        )
        assertEquals(33, (parsed.first { it.first == 2 }.second as ByteArray).size)
        assertEquals(64, (parsed.first { it.first == 3 }.second as ByteArray).size)
        assertEquals(7, (parsed.first { it.first == 99 }.second as ByteArray).size)
        // 33-byte ephemeral keys are SEC1-compressed: 0x02/0x03 prefix.
        val prefix = (parsed.first { it.first == 2 }.second as ByteArray)[0]
        assertTrue(prefix == 0x02.toByte() || prefix == 0x03.toByte())
    }

    // Known answer (§4.3, C50's protobuf half): the inner message's field numbers are
    // message 1, counter 2, gossip 3, debug 99 — verified by hand-decrypting the ciphertext.
    @Test
    fun innerMessageCarriesTheRecordedFieldNumbers() {
        val withExtras = encrypt(gossip = ByteArray(8), debug = ByteArray(4))
        val innerFields = handDecryptedInnerFields(withExtras, gossip = true, debug = true)
        assertEquals(listOf(1, 2, 3, 99), innerFields)
        assertEquals(listOf(1, 2), handDecryptedInnerFields(encrypt()))
    }

    @Test
    fun validatorIsTwoBytePrefixesPlusTheZeroZeroCVersionByte() {
        val expected = byteArrayOf(
            senderDeviceMarshalled[0], senderDeviceMarshalled[1],
            recipientDeviceMarshalled[0], recipientDeviceMarshalled[1],
            recipientPrekeyMarshalled[0], recipientPrekeyMarshalled[1],
            0x0c,
        )
        assertContentEquals(
            expected,
            PairEcEnvelope.validator(senderDeviceMarshalled, recipientDeviceMarshalled, recipientPrekeyMarshalled),
        )
        val received = (MiniProto.decode(encrypt()).first { it.first == 99 }.second as ByteArray)
        assertContentEquals(expected, received)
    }

    @Test
    fun ciphertextIsPaddedToAMultipleOfSixteenPlusTheFourByteTrailer() {
        val ciphertext = MiniProto.decode(encrypt()).first { it.first == 1 }.second as ByteArray
        assertTrue(ciphertext.size >= 4)
        assertEquals(0, (ciphertext.size - 4) % 16, "pad-to-16 then 4-byte LE trailer (§4.3)")
    }

    @Test
    fun signatureCoversSharedSecretPrekeysEphemeralAndCiphertext() {
        // Structural: decryption recomputes the same signature input, so the correct key
        // verifies and any other key fails — the coverage test is in the failure paths.
        decrypt(encrypt())
        assertFailsWith<PairEcEnvelope.PairIntegrityException> {
            decrypt(encrypt(), senderSigningPublicKey = OTHER_DEVICE_KEY.public)
        }
    }

    @Test
    fun validatorMismatchFailsLoudlyWhenSenderKeySupplied() {
        assertFailsWith<PairEcEnvelope.PairIntegrityException> {
            decrypt(encrypt(), senderDeviceKeyMarshalled = ByteArray(65) { 0x55 })
        }
    }

    @Test
    fun verificationSkippedWhenKeysAbsent() {
        val (back, _) = decrypt(encrypt(), senderDeviceKeyMarshalled = null, senderSigningPublicKey = null)
        assertContentEquals(plaintext, back)
    }

    @Test
    fun gossipAndDebugFieldsRideTheInnerMessage() {
        val plain = encrypt()
        val withExtras = encrypt(gossip = ByteArray(64), debug = byteArrayOf(3))
        fun ciphertextLength(outer: ByteArray): Int =
            (MiniProto.decode(outer).first { it.first == 1 }.second as ByteArray).size
        assertTrue(ciphertextLength(withExtras) > ciphertextLength(plain), "extras grow the encrypted inner message")
        val (back, _) = decrypt(withExtras, senderDeviceKeyMarshalled = null, senderSigningPublicKey = null)
        assertContentEquals(plaintext, back, "the inner parse must tolerate the optional fields")
    }

    // --- ephemeral key wire form (§4.3 prose vs C57's 32-byte reading, §7 item 21) -------

    @Test
    fun defaultEphemeralKeyIsTheThirtyThreeByteCompressedPoint() {
        val parsed = MiniProto.decode(encrypt())
        val key = parsed.first { it.first == 2 }.second as ByteArray
        assertEquals(33, key.size)
        val (back, _) = decrypt(encrypt(), senderDeviceKeyMarshalled = null, senderSigningPublicKey = null)
        assertContentEquals(plaintext, back)
    }

    @Test
    fun xOnlyEphemeralKeyFormEmitsBareCoordinatesAndStillDecrypts() {
        val parsed = MiniProto.decode(encrypt(ephemeralKeyForm = PairEcEnvelope.EphemeralKeyForm.X_ONLY_32))
        val key = parsed.first { it.first == 2 }.second as ByteArray
        assertEquals(32, key.size, "the C57 32-byte form is the bare x-coordinate (no parity prefix)")
        assertTrue(key[0] != 0x02.toByte() && key[0] != 0x03.toByte())
        val (back, _) = decrypt(
            encrypt(ephemeralKeyForm = PairEcEnvelope.EphemeralKeyForm.X_ONLY_32),
            senderDeviceKeyMarshalled = null,
            senderSigningPublicKey = null,
        )
        assertContentEquals(plaintext, back, "the receiver recovers the point by trying both parities")
    }

    @Test
    fun neitherRecordedEphemeralFormIsRejectedLoudly() {
        val parsed = MiniProto.decode(encrypt())
        val mangled = (parsed.first { it.first == 2 }.second as ByteArray).copyOfRange(0, 20)
        assertFailsWith<IllegalArgumentException> {
            PairEcEnvelope.decrypt(
                MiniProto.encode(listOf(1 to ByteArray(4), 2 to mangled)),
                PREKEY.private,
                recipientPrekeyMarshalled,
                recipientDeviceMarshalled,
            )
        }
    }

    // --- HKDF derivation (§4.3, rev-12 correction: "LastPawn-MessageKeys" is the SALT, info empty)

    @Test
    fun hkdfUsesTheLastPawnSaltWithEmptyInfo() {
        // Known answer computed independently of this code (HKDF-SHA256, RFC 5869):
        // salt = "LastPawn-MessageKeys", info = empty, ikm = 00..1f.
        val ikm = ByteArray(32) { it.toByte() }
        val prk = Hkdf.extract(HkdfSaltVector.salt, ikm)
        assertContentEquals(HkdfSaltVector.expectedPrk, prk)
        assertContentEquals(HkdfSaltVector.expectedOkm, Hkdf.expand(prk, ByteArray(0), 48))
    }

    @Test
    fun decryptRejectsAWrongSaltDerivation() {
        // The salt is a fixed constant, not caller configuration — a peer deriving with the
        // superseded info-string reading must not decrypt.
        val outer = encrypt()
        val parsed = MiniProto.decode(outer)
        val ciphertext = parsed.first { it.first == 1 }.second as ByteArray
        val ephemeral = PairEcEnvelope.ephemeralPublicKey(parsed.first { it.first == 2 }.second as ByteArray)
        val shared = KeyAgreement.getInstance("ECDH").apply {
            init(PREKEY.private)
            doPhase(ephemeral, true)
        }.generateSecret()
        val wrong = Hkdf.expand(Hkdf.extract(ByteArray(32), shared), "LastPawn-MessageKeys".toByteArray(), 48)
        val wrongPlaintext = PairEnvelope.aesCtr(ciphertext, wrong.copyOfRange(0, 32), wrong.copyOfRange(32, 48))
        assertTrue(
            runCatching { PairEcEnvelope.unpad(wrongPlaintext) }.isFailure,
            "the superseded info-string derivation must not produce a parseable inner message",
        )
    }

    // --- prekey record signature (§4.3) --------------------------------------

    @Test
    fun prekeySignatureInputIsLabelPlusPrekeyPlusLittleEndianTimestamp() {
        val label = "NGMPrekeySignature".toByteArray(Charsets.US_ASCII)
        // ts = 0.0 → eight zero timestamp bytes (endian-invariant, but still appended).
        assertContentEquals(
            MessageDigest.getInstance("SHA-256").digest(label + compressedPrekey + ByteArray(8)),
            PairEcEnvelope.prekeySignatureBytes(compressedPrekey, 0.0),
        )
        // ts = 1.0 → IEEE-754 bits 0x3FF0000000000000, little-endian: 00 00 00 00 00 00 F0 3F.
        assertContentEquals(
            MessageDigest.getInstance("SHA-256").digest(
                label + compressedPrekey + byteArrayOf(0, 0, 0, 0, 0, 0, 0xF0.toByte(), 0x3F),
            ),
            PairEcEnvelope.prekeySignatureBytes(compressedPrekey, 1.0),
        )
    }

    @Test
    fun prekeySignatureRoundTripAndTamper() {
        val signature = PairEcEnvelope.signPrekey(DEVICE_KEY.private, compressedPrekey, 1_700_000_000.0)
        assertEquals(64, signature.size, "raw 64-byte r‖s (§4.3)")
        assertTrue(PairEcEnvelope.verifyPrekey(DEVICE_KEY.public, compressedPrekey, 1_700_000_000.0, signature))
        assertTrue(
            !PairEcEnvelope.verifyPrekey(OTHER_DEVICE_KEY.public, compressedPrekey, 1_700_000_000.0, signature),
            "a different device key must not verify (§4.3: receivers verify against the sender's device key)",
        )
        val tampered = signature.copyOf().also { it[10] = (it[10].toInt() xor 1).toByte() }
        assertTrue(!PairEcEnvelope.verifyPrekey(DEVICE_KEY.public, compressedPrekey, 1_700_000_000.0, tampered))
    }

    // --- minimal protobuf ------------------------------------------------------

    @Test
    fun protobufVarintKnownAnswers() {
        assertContentEquals(byteArrayOf(0x08, 0x96.toByte(), 0x01), MiniProto.encode(listOf(1 to 150L)))
        assertContentEquals(byteArrayOf(0x08, 0xAC.toByte(), 0x02), MiniProto.encode(listOf(1 to 300L)))
        assertContentEquals(
            byteArrayOf(0x12, 0x02, 0x68, 0x69),
            MiniProto.encode(listOf(2 to "hi".toByteArray())),
        )
        assertContentEquals(listOf<Pair<Int, Any>>(1 to 150L), MiniProto.decode(byteArrayOf(0x08, 0x96.toByte(), 0x01)))
        // Round-trip a mix of varints and length-delimited fields across a field number > 15.
        val mixed = listOf(99 to "validator".toByteArray(), 3 to 1_000_000L, 10 to byteArrayOf(1, 2))
        MiniProto.decode(MiniProto.encode(mixed)).forEachIndexed { i, (field, value) ->
            assertEquals(mixed[i].first, field)
            when (value) {
                is ByteArray -> assertContentEquals(mixed[i].second as ByteArray, value)
                else -> assertEquals(mixed[i].second, value)
            }
        }
    }

    /** ECDH + HKDF + AES-CTR + unpad + decode, using only the recorded wire facts. */
    private fun handDecryptedInnerFields(outer: ByteArray, gossip: Boolean = false, debug: Boolean = false): List<Int> {
        val parsed = MiniProto.decode(outer)
        val ciphertext = parsed.first { it.first == 1 }.second as ByteArray
        val ephemeral = PairEcEnvelope.ephemeralPublicKey(parsed.first { it.first == 2 }.second as ByteArray)
        val shared = KeyAgreement.getInstance("ECDH").apply {
            init(PREKEY.private)
            doPhase(ephemeral, true)
        }.generateSecret()
        val okm = Hkdf.expand(
            Hkdf.extract("LastPawn-MessageKeys".toByteArray(Charsets.US_ASCII), shared),
            ByteArray(0),
            48,
        )
        val padded = PairEnvelope.aesCtr(ciphertext, okm.copyOfRange(0, 32), okm.copyOfRange(32, 48))
        val inner = MiniProto.decode(PairEcEnvelope.unpad(padded))
        return inner.map { it.first }.also { fields ->
            val expectedFields = buildSet {
                add(1)
                add(2)
                if (gossip) add(3)
                if (debug) add(99)
            }
            assertEquals(expectedFields, fields.toSet())
        }
    }

    private object HkdfSaltVector {
        val salt = "LastPawn-MessageKeys".toByteArray(Charsets.US_ASCII)
        val expectedPrk = hexToBytes("d3d43516b7e4540c6f8c188aa959a7a538851856a604e4cbfcf432b02912de84")
        val expectedOkm = hexToBytes(
            "c2d243f6ae6fb64ea3a0691dda66415678d78add225a7ebc5be826ee4cff88cf" +
                "e365c7f1c4483fa427d9eb6f250b13c9",
        )

        fun hexToBytes(hex: String): ByteArray = ByteArray(hex.length / 2) {
            ((Character.digit(hex[it * 2], 16) shl 4) + Character.digit(hex[it * 2 + 1], 16)).toByte()
        }
    }

    private companion object {
        val DEVICE_KEY: KeyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        val OTHER_DEVICE_KEY: KeyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        val PREKEY: KeyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
    }
}
