package dev.fenn.imessage.registration

import java.security.KeyPairGenerator
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Synthetic-vector tests for the §1.1 step-2 request blob (C56-a; spec §1.1 rev 35). */
class NacRequestBlobTest {

    private class FixedDraw(values: List<ByteArray>) {
        val drawn = mutableListOf<ByteArray>()
        private val queue = ArrayDeque(values)
        fun next(n: Int): ByteArray {
            val v = queue.removeFirst()
            assertEquals(n, v.size, "draw size")
            drawn.add(v)
            return v
        }
    }

    private fun keyPair() = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    private fun blob(publicKey: java.security.PublicKey, draw: FixedDraw): Pair<ByteArray, ByteArray> {
        val pearKey16 = ByteArray(16) { (it * 17 + 3).toByte() }
        val out = NacRequestBlob.build(publicKey, pearKey16) { n -> draw.next(n) }
        return out to pearKey16
    }

    @Test
    fun blobShape() {
        val pair = keyPair()
        val draw = FixedDraw(
            listOf(
                ByteArray(20) { it.toByte() },   // hmacKey20
                ByteArray(16) { (it + 1).toByte() }, // innerKey16
                ByteArray(16) { (it + 2).toByte() }, // slot16
                ByteArray(16) { (it + 3).toByte() }, // iv16
            ),
        )
        val (blob, pearKey16) = blob(pair.public, draw)
        assertEquals(NacRequestBlob.BLOB_BYTES, blob.size)
        assertContentEquals(NacRequestBlob.header, blob.copyOfRange(0, 10))
        // slot16 rides at [266:282], followed by the u32be(32) length marker
        assertContentEquals(draw.drawn[2], blob.copyOfRange(266, 282))
        assertContentEquals(byteArrayOf(0, 0, 0, 0x20), blob.copyOfRange(282, 286))
        // OAEP decrypt round-trip: the plaintext is pearKey16 ‖ hmacKey20
        val cipher = javax.crypto.Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding")
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, pair.private)
        val plain = cipher.doFinal(blob.copyOfRange(10, 266))
        assertEquals(36, plain.size)
        assertContentEquals(pearKey16, plain.copyOfRange(0, 16))
        assertContentEquals(draw.drawn[0], plain.copyOfRange(16, 36))
        // the tail is HMAC-SHA1(hmacKey20, field32)
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(draw.drawn[0], "HmacSHA1"))
        assertContentEquals(mac.doFinal(blob.copyOfRange(286, 318)), blob.copyOfRange(318, 338))
    }

    @Test
    fun field32IsMappedEncryptedPayload() {
        val hmacKey20 = ByteArray(20) { (0x40 + it).toByte() }
        val innerKey16 = ByteArray(16) { (0x50 + it).toByte() }
        val slot16 = ByteArray(16) { (0x60 + it).toByte() }
        val iv16 = ByteArray(16) { (0x70 + it).toByte() }
        val draw = FixedDraw(listOf(hmacKey20, innerKey16, slot16, iv16))
        val (blob, pearKey16) = blob(keyPair().public, draw)

        val plain32 = ByteArray(32)
        plain32[0] = 0x02
        plain32[4] = 0x01
        innerKey16.copyInto(plain32, 5)
        val mappedPlain = ByteArray(32) { i -> PearTables.blobPayloadMap[plain32[i].toInt() and 0xff] }
        val enc32 = PearAes.encryptCbc(mappedPlain, iv16, PearAes.initKey(pearKey16))
        val field32 = ByteArray(32) { i -> PearTables.blobFieldMap[enc32[i].toInt() and 0xff] }
        assertContentEquals(field32, blob.copyOfRange(286, 318))
    }

    @Test
    fun rejectsWrongPearKeySize() {
        val draw = FixedDraw(listOf(ByteArray(20), ByteArray(16), ByteArray(16), ByteArray(16)))
        assertFailsWith<IllegalArgumentException> {
            NacRequestBlob.build(keyPair().public, ByteArray(15)) { n -> draw.next(n) }
        }
    }

    @Test
    fun publicBuildIsRandomizedAndWellFormed() {
        val pearKey16 = ByteArray(16).also(SecureRandom()::nextBytes)
        val blob = NacRequestBlob.build(keyPair().public, pearKey16, SecureRandom())
        assertEquals(NacRequestBlob.BLOB_BYTES, blob.size)
        assertContentEquals(NacRequestBlob.header, blob.copyOfRange(0, 10))
        val blob2 = NacRequestBlob.build(keyPair().public, pearKey16, SecureRandom())
        // fresh randomness per build: the OAEP ciphertext (padded RSA) must differ
        assertTrue(!blob.contentEquals(blob2))
    }
}
