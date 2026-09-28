package dev.fenn.imessage.ids

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class IdsSigningTest {

    private val fixedMillis = 1_700_000_000_000L

    // Known answer for fixedMillis = 1700000000000 = 0x0000018BCFE56800 (spec §1.4 nonce layout).
    private val expectedMillisBytes = byteArrayOf(
        0x00, 0x00, 0x01, 0x8B.toByte(), 0xCF.toByte(), 0xE5.toByte(), 0x68, 0x00,
    )
    private val expectedRandomBytes = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)

    private fun fixedRandom() = object : SecureRandom() {
        override fun nextBytes(bytes: ByteArray) {
            for (i in bytes.indices) bytes[i] = (i + 1).toByte()
        }
    }

    @Test
    fun nonceIsTypeByteThenBigEndianMillisThenRandom() {
        val nonce = IdsSigning.nonce(IdsSigning.TYPE_HTTPS, fixedMillis, fixedRandom())

        assertEquals(17, nonce.size)
        assertEquals(0x01, nonce[0].toInt())
        assertContentEquals(expectedMillisBytes, nonce.copyOfRange(1, 9))
        assertContentEquals(expectedRandomBytes, nonce.copyOfRange(9, 17))
    }

    @Test
    fun nonceTypeByteIsTheOnlyDifference() {
        val apns = IdsSigning.nonce(IdsSigning.TYPE_APNS, fixedMillis, fixedRandom())
        assertEquals(0x00, apns[0].toInt())
        assertFailsWith<IllegalArgumentException> { IdsSigning.nonce(0x42.toByte(), fixedMillis, fixedRandom()) }
    }

    @Test
    fun signingBytesAreNonceThenLengthPrefixedFields() {
        val nonce = IdsSigning.nonce(IdsSigning.TYPE_HTTPS, fixedMillis, fixedRandom())
        val bytes = IdsSigning.signingBytes(nonce, listOf("id-query".toByteArray(), ByteArray(0), byteArrayOf(0xAA.toByte())))

        // nonce | 00 00 00 08 "id-query" | 00 00 00 00 | 00 00 00 01 AA
        val expected = nonce +
            byteArrayOf(0, 0, 0, 8) + "id-query".toByteArray() +
            byteArrayOf(0, 0, 0, 0) +
            byteArrayOf(0, 0, 0, 1, 0xAA.toByte())
        assertContentEquals(expected, bytes)
        assertEquals(17 + 12 + 4 + 5, bytes.size)
    }

    @Test
    fun nonceLengthIsEnforced() {
        assertFailsWith<IllegalArgumentException> { IdsSigning.signingBytes(ByteArray(16), emptyList()) }
    }

    @Test
    fun signatureIsPrefixedAndVerifiesOverTheSigningBytes() {
        val nonce = IdsSigning.nonce(IdsSigning.TYPE_HTTPS, fixedMillis, fixedRandom())
        val fields = listOf("id-query".toByteArray(), ByteArray(0), "body".toByteArray(), byteArrayOf(9, 9, 9))
        val signature = IdsSigning.sign(RSA_KEY.private, nonce, fields)

        assertContentEquals(byteArrayOf(0x01, 0x01), signature.copyOfRange(0, 2))
        assertTrue(verify(RSA_KEY, nonce, fields, signature))
        // A different push token must not verify against that signature.
        assertFalse(verify(RSA_KEY, nonce, listOf("id-query".toByteArray(), ByteArray(0), "body".toByteArray(), byteArrayOf(8, 8, 8)), signature))
    }

    private fun verify(keyPair: KeyPair, nonce: ByteArray, fields: List<ByteArray>, signature: ByteArray): Boolean {
        val verifier = Signature.getInstance("SHA1withRSA")
        verifier.initVerify(keyPair.public)
        verifier.update(IdsSigning.signingBytes(nonce, fields))
        return verifier.verify(signature.copyOfRange(2, signature.size))
    }

    private companion object {
        /** Test-only key, generated per class — never a hardcoded key. */
        val RSA_KEY: KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair()
    }
}
