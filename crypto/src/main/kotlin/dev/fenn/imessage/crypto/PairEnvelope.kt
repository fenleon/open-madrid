package dev.fenn.imessage.crypto

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The §4.2 legacy "pair" encryption envelope — pure JCE, no third-party crypto.
 *
 * Wire form (§4.2): a 0x02 tag byte, a 2-byte big-endian body length, the body, a 1-byte
 * signature length, then the signature. The body is the 160-byte RSA-OAEP block (AES-128
 * message key ‖ first min(100, len) ciphertext bytes — a shorter ciphertext transports
 * only what exists) followed by the remaining ciphertext in the clear.
 *
 * Recorded constructions (rev 12, C51 closed — §4.2):
 * - the 40-bit integrity value is HMAC-SHA-256 **keyed with the 11 random bytes
 *   themselves**, over plaintext ‖ 0x02 ‖ sender-identity-hash ‖ recipient-identity-hash;
 *   only its first 5 bytes are used, appended to the 11-byte seed to form the AES-128 key,
 *   and the HMAC is never placed in the envelope;
 * - an identity hash is SHA-256 over the concatenated marshalled signing + encryption key
 *   blobs (the caller's published-identity sub-blobs: the ASN.1-style blob's signing point
 *   and RSA-1280 key, each with a 2-byte type prefix);
 * - the RSA-OAEP block is SHA-1 (MGF1-SHA1, empty label) under the recipient's RSA
 *   encryption key;
 * - the signature is SHA1withECDSA (P-256) over the exact body bytes, DER/ASN.1-encoded.
 *
 * Envelope *selection* between this and [PairEcEnvelope] is unresolved (spec §4.5, §7 item
 * 1, C25) — this codec builds both schemes and invents no selection rule.
 */
object PairEnvelope {

    /** Envelope tag byte (§4.2). */
    const val TAG: Byte = 0x02

    /** RSA block size: 1280-bit key → 160 bytes; a decryptable body is at least this long. */
    const val RSA_BLOCK_BYTES = 160

    /** Maximum bytes of ciphertext carried inside the RSA block after the 16-byte message key. */
    const val KEY_TRANSPORT_CIPHERTEXT_BYTES = 100

    const val MESSAGE_KEY_BYTES = 16 // 11 random + 5 HMAC-derived (§4.2)

    fun identityHash(firstMarshalledKey: ByteArray, secondMarshalledKey: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(firstMarshalledKey + secondMarshalledKey)

    /** The full 32-byte HMAC, keyed with the 11 random bytes (§4.2); the envelope uses its first 5 bytes. */
    fun integrityHmac(
        randomKeyBytes: ByteArray,
        plaintext: ByteArray,
        senderIdentityHash: ByteArray,
        recipientIdentityHash: ByteArray,
    ): ByteArray = Hkdf.hmac(randomKeyBytes, plaintext + byteArrayOf(TAG) + senderIdentityHash + recipientIdentityHash)

    fun messageKey(randomPart: ByteArray, integrityPart: ByteArray): ByteArray {
        require(randomPart.size == MESSAGE_KEY_BYTES - 5) { "random part must be 11 bytes" }
        require(integrityPart.size == 5) { "integrity part must be 5 bytes" }
        return randomPart + integrityPart
    }

    /** Fixed IV (§4.2): 15 zero bytes followed by 0x01. */
    fun iv(): ByteArray = ByteArray(15) + byteArrayOf(0x01)

    fun encrypt(
        plaintext: ByteArray,
        senderSigningKey: PrivateKey,
        recipientEncryptionKey: PublicKey,
        senderIdentityHash: ByteArray,
        recipientIdentityHash: ByteArray,
        random: SecureRandom,
    ): ByteArray {
        val randomPart = ByteArray(MESSAGE_KEY_BYTES - 5).also { random.nextBytes(it) }
        val integrity = integrityHmac(randomPart, plaintext, senderIdentityHash, recipientIdentityHash)
            .copyOfRange(0, 5)
        val key = messageKey(randomPart, integrity)
        val ciphertext = aesCtr(plaintext, key, iv())
        // §4.2: the RSA block transports the key plus the first min(100, len) ciphertext bytes.
        val transported = ciphertext.copyOfRange(0, minOf(KEY_TRANSPORT_CIPHERTEXT_BYTES, ciphertext.size))

        val rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding")
        rsa.init(Cipher.ENCRYPT_MODE, recipientEncryptionKey, random)
        val rsaBlock = rsa.doFinal(key + transported)
        if (rsaBlock.size != RSA_BLOCK_BYTES) {
            throw IllegalStateException("RSA block is ${rsaBlock.size} bytes, expected $RSA_BLOCK_BYTES (1280-bit key?)")
        }
        val body = rsaBlock + ciphertext.copyOfRange(transported.size, ciphertext.size)
        val signature = sign(senderSigningKey, body)
        if (signature.size > 0xFF) throw IllegalStateException("signature longer than the 1-byte length")
        return ByteBuffer.allocate(1 + 2 + body.size + 1 + signature.size)
            .put(TAG)
            .putShort(body.size.toShort())
            .put(body)
            .put(signature.size.toByte())
            .put(signature)
            .array()
    }

    /**
     * Decrypts and integrity-checks. Verifies the sender's signature only when
     * [senderSigningPublicKey] is given (§4.2: third-party clients may skip verification).
     * Throws [IllegalArgumentException] on malformed envelopes and [PairIntegrityException]
     * on a 40-bit integrity mismatch or a failed signature check.
     */
    fun decrypt(
        envelope: ByteArray,
        recipientDecryptionKey: PrivateKey,
        senderSigningPublicKey: PublicKey?,
        senderIdentityHash: ByteArray,
        recipientIdentityHash: ByteArray,
    ): ByteArray {
        if (envelope.size < 1 + 2 + 1) throw IllegalArgumentException("envelope too short (${envelope.size} B)")
        if (envelope[0] != TAG) throw IllegalArgumentException("bad tag 0x%02x, expected 0x02".format(envelope[0]))
        val bodyLength = ((envelope[1].toInt() and 0xFF) shl 8) or (envelope[2].toInt() and 0xFF)
        val signatureLength = envelope[3 + bodyLength].toInt() and 0xFF
        if (1 + 2 + bodyLength + 1 + signatureLength != envelope.size) {
            throw IllegalArgumentException("envelope length mismatch (${envelope.size} B vs $bodyLength B body)")
        }
        if (bodyLength < RSA_BLOCK_BYTES) {
            throw IllegalArgumentException("body of $bodyLength B is shorter than the $RSA_BLOCK_BYTES-byte RSA block")
        }
        val body = envelope.copyOfRange(3, 3 + bodyLength)
        val signature = envelope.copyOfRange(4 + bodyLength, envelope.size)
        senderSigningPublicKey?.let {
            val verifier = Signature.getInstance("SHA1withECDSA")
            verifier.initVerify(it)
            verifier.update(body)
            if (!verifier.verify(signature)) throw PairIntegrityException("signature verification failed")
        }

        val rsaBlock = body.copyOfRange(0, RSA_BLOCK_BYTES)
        val clearTail = body.copyOfRange(RSA_BLOCK_BYTES, body.size)
        val rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding")
        rsa.init(Cipher.DECRYPT_MODE, recipientDecryptionKey)
        val transported = rsa.doFinal(rsaBlock)
        if (transported.size < MESSAGE_KEY_BYTES) {
            throw IllegalArgumentException("RSA block decrypted to ${transported.size} B; no room for the message key")
        }
        val key = transported.copyOfRange(0, MESSAGE_KEY_BYTES)
        // min(100, len) transport (§4.2): the decrypted block's size tells how much rode inside it.
        val ciphertext = transported.copyOfRange(MESSAGE_KEY_BYTES, transported.size) + clearTail
        val plaintext = aesCtr(ciphertext, key, iv())
        val expected = integrityHmac(key.copyOfRange(0, MESSAGE_KEY_BYTES - 5), plaintext, senderIdentityHash, recipientIdentityHash)
            .copyOfRange(0, 5)
        if (!expected.contentEquals(key.copyOfRange(MESSAGE_KEY_BYTES - 5, MESSAGE_KEY_BYTES))) {
            throw PairIntegrityException("40-bit integrity value mismatch")
        }
        return plaintext
    }

    class PairIntegrityException(message: String) : IllegalStateException(message)

    private fun sign(key: PrivateKey, body: ByteArray): ByteArray {
        val signer = Signature.getInstance("SHA1withECDSA")
        signer.initSign(key)
        signer.update(body)
        return signer.sign()
    }

    internal fun aesCtr(data: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(data)
    }
}
