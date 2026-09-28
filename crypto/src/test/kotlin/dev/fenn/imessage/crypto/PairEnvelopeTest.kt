package dev.fenn.imessage.crypto

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PairEnvelopeTest {

    private val plaintext = MessageBody(
        text = "pair envelope test with enough bytes that the ciphertext clears the " +
            "hundred-byte RSA transport window comfortably",
        protocolVersion = "1",
    ).encode()
    private val senderIdentityHash = ByteArray(32) { (it + 1).toByte() }
    private val recipientIdentityHash = ByteArray(32) { (it + 9).toByte() }

    /** Seeded RNG: the 11 random message-key bytes are deterministic (1, 2, 3, …). */
    private fun fixedRandom(seed: Byte = 1) = object : SecureRandom() {
        private var next = seed
        override fun nextBytes(bytes: ByteArray) {
            for (i in bytes.indices) bytes[i] = (next + i).toByte()
            next = (next + bytes.size).toByte()
        }
    }

    private fun encryptEnvelope(random: SecureRandom = fixedRandom()): ByteArray = PairEnvelope.encrypt(
        plaintext = plaintext,
        senderSigningKey = EC_KEY.private,
        recipientEncryptionKey = RSA_KEY.public,
        senderIdentityHash = senderIdentityHash,
        recipientIdentityHash = recipientIdentityHash,
        random = random,
    )

    // Known answer: identityHash is SHA-256 over the plain concatenation of the two marshalled
    // keys — with an empty second key it must equal SHA-256 of the first ("abc" vector).
    @Test
    fun identityHashIsSha256OverThePlainConcatenation() {
        val expected = hexToBytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        assertContentEquals(expected, PairEnvelope.identityHash("abc".toByteArray(), ByteArray(0)))
    }

    // RFC 4231 test case 2 for the HMAC primitive.
    @Test
    fun hmacPrimitiveMatchesRfc4231() {
        val mac = Hkdf.hmac("Jefe".toByteArray(), "what do ya want for nothing?".toByteArray())
        assertContentEquals(hexToBytes("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"), mac)
    }

    // §4.2 (C51): the 40-bit integrity HMAC is keyed with the 11 random bytes themselves and
    // computed over plaintext ‖ 0x02 ‖ sender-identity-hash ‖ recipient-identity-hash.
    @Test
    fun integrityHmacIsKeyedByTheRandomBytesAndCoversPlaintextTagAndBothIdentityHashes() {
        val randomPart = ByteArray(11) { (it + 3).toByte() }
        val expected = Hkdf.hmac(
            randomPart,
            plaintext + byteArrayOf(PairEnvelope.TAG) + senderIdentityHash + recipientIdentityHash,
        )
        assertContentEquals(
            expected,
            PairEnvelope.integrityHmac(randomPart, plaintext, senderIdentityHash, recipientIdentityHash),
        )
        assertTrue(
            !expected.contentEquals(
                Hkdf.hmac(ByteArray(11) { 9 }, plaintext + byteArrayOf(PairEnvelope.TAG) + senderIdentityHash + recipientIdentityHash),
            ),
            "a different 11-byte key must produce a different integrity value",
        )
    }

    @Test
    fun messageKeyIsElevenRandomBytesThenTheFiveIntegrityBytes() {
        val key = PairEnvelope.messageKey(ByteArray(11) { it.toByte() }, byteArrayOf(9, 8, 7, 6, 5))
        assertContentEquals(byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 9, 8, 7, 6, 5), key)
        assertFailsWith<IllegalArgumentException> { PairEnvelope.messageKey(ByteArray(10), byteArrayOf(1, 2, 3, 4, 5)) }
        assertFailsWith<IllegalArgumentException> { PairEnvelope.messageKey(ByteArray(11), ByteArray(6)) }
    }

    @Test
    fun ivIsFifteenZeroBytesThenOne() {
        assertContentEquals(ByteArray(15) + byteArrayOf(0x01), PairEnvelope.iv())
    }

    @Test
    fun envelopeStructure() {
        val envelope = encryptEnvelope()
        assertEquals(PairEnvelope.TAG, envelope[0])
        val bodyLength = ((envelope[1].toInt() and 0xFF) shl 8) or (envelope[2].toInt() and 0xFF)
        val signatureLength = envelope[3 + bodyLength].toInt() and 0xFF
        assertEquals(envelope.size, 3 + bodyLength + 1 + signatureLength)
        assertTrue(bodyLength >= PairEnvelope.RSA_BLOCK_BYTES, "a decryptable body is at least the RSA block")
        // CTR preserves length: body = 160-byte RSA block + the ciphertext past its first 100 bytes.
        assertEquals(
            PairEnvelope.RSA_BLOCK_BYTES - PairEnvelope.KEY_TRANSPORT_CIPHERTEXT_BYTES + plaintext.size,
            bodyLength,
        )
    }

    @Test
    fun roundTripWithSignatureVerification() {
        val decrypted = PairEnvelope.decrypt(
            envelope = encryptEnvelope(),
            recipientDecryptionKey = RSA_KEY.private,
            senderSigningPublicKey = EC_KEY.public,
            senderIdentityHash = senderIdentityHash,
            recipientIdentityHash = recipientIdentityHash,
        )
        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun decryptSkipsSignatureVerificationWhenKeyAbsent() {
        val decrypted = PairEnvelope.decrypt(
            encryptEnvelope(),
            RSA_KEY.private,
            senderSigningPublicKey = null,
            senderIdentityHash,
            recipientIdentityHash,
        )
        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun wrongSigningKeyFailsVerification() {
        assertFailsWith<PairEnvelope.PairIntegrityException> {
            PairEnvelope.decrypt(
                encryptEnvelope(),
                RSA_KEY.private,
                OTHER_EC_KEY.public,
                senderIdentityHash,
                recipientIdentityHash,
            )
        }
    }

    @Test
    fun tamperedCiphertextFailsTheFortyBitIntegrityCheck() {
        val envelope = encryptEnvelope().copyOf()
        // Flip a byte in the clear tail (first byte after the RSA block) — the plaintext changes,
        // so the HMAC-derived 40 bits must stop matching.
        val clearTailStart = 3 + PairEnvelope.RSA_BLOCK_BYTES
        envelope[clearTailStart] = (envelope[clearTailStart].toInt() xor 0x55).toByte()
        assertFailsWith<PairEnvelope.PairIntegrityException> {
            PairEnvelope.decrypt(envelope, RSA_KEY.private, null, senderIdentityHash, recipientIdentityHash)
        }
    }

    @Test
    fun tamperedRandomKeyBytesFailLoudly() {
        // The integrity HMAC is keyed by the transported 11 random bytes (§4.2, C51): flipping
        // one inside the RSA block must never yield a clean decrypt (OAEP may reject the
        // mangled block outright, or the 40-bit check fires).
        val envelope = encryptEnvelope().copyOf()
        envelope[3] = (envelope[3].toInt() xor 0x01).toByte()
        val outcome = runCatching {
            PairEnvelope.decrypt(envelope, RSA_KEY.private, null, senderIdentityHash, recipientIdentityHash)
        }
        assertTrue(outcome.isFailure, "mangling the transported random key bytes must fail loudly")
    }

    @Test
    fun malformedEnvelopesRejected() {
        val good = encryptEnvelope()
        assertFailsWith<IllegalArgumentException> { PairEnvelope.decrypt(ByteArray(3), RSA_KEY.private, null, senderIdentityHash, recipientIdentityHash) }
        assertFailsWith<IllegalArgumentException> {
            val badTag = good.copyOf().also { it[0] = 0x03 }
            PairEnvelope.decrypt(badTag, RSA_KEY.private, null, senderIdentityHash, recipientIdentityHash)
        }
        assertFailsWith<IllegalArgumentException> {
            PairEnvelope.decrypt(good.copyOfRange(0, good.size - 5), RSA_KEY.private, null, senderIdentityHash, recipientIdentityHash)
        }
    }

    @Test
    fun shortPlaintextTransportsOnlyWhatExists() {
        // §4.2 (C51): the RSA block carries the key plus the first min(100, len) ciphertext
        // bytes — a shorter ciphertext fills only what exists and nothing rides in the clear.
        val tiny = "tiny".toByteArray()
        val envelope = PairEnvelope.encrypt(
            plaintext = tiny,
            senderSigningKey = EC_KEY.private,
            recipientEncryptionKey = RSA_KEY.public,
            senderIdentityHash = senderIdentityHash,
            recipientIdentityHash = recipientIdentityHash,
            random = fixedRandom(),
        )
        val bodyLength = ((envelope[1].toInt() and 0xFF) shl 8) or (envelope[2].toInt() and 0xFF)
        assertEquals(PairEnvelope.RSA_BLOCK_BYTES, bodyLength, "a sub-100-byte ciphertext leaves no clear tail")
        val decrypted = PairEnvelope.decrypt(envelope, RSA_KEY.private, EC_KEY.public, senderIdentityHash, recipientIdentityHash)
        assertContentEquals(tiny, decrypted)
    }

    private fun hexToBytes(hex: String): ByteArray = ByteArray(hex.length / 2) {
        ((Character.digit(hex[it * 2], 16) shl 4) + Character.digit(hex[it * 2 + 1], 16)).toByte()
    }

    private companion object {
        val EC_KEY: KeyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        val OTHER_EC_KEY: KeyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        /** 1280-bit RSA encryption key — the §4.2 identity encryption key size (160-byte block). */
        val RSA_KEY: KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(1280) }.generateKeyPair()
    }
}
