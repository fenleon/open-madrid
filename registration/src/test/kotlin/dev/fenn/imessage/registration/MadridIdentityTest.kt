package dev.fenn.imessage.registration

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertNotNull

/**
 * Shape parity of the madrid identity blobs against the captured genuine §1.4 register
 * (ob-trap-20261014-201103 frame-026): identity-key 249 B (RSA-1280), prekey 109 B,
 * kt-loggable-data 40 B — and the prekey signature verifies against the device key.
 */
class MadridIdentityTest {

    private val identity = MadridIdentity.generate()

    @Test
    fun identityKeyDerIsTheCapturedShape() {
        val der = identity.identityKeyDer()
        // 3 (SEQ header `30 81 f6`) + ctx1 (tag + len + 67 = 69) + ctx2 (tag + len + 174 = 177)
        // = 249 at RSA-1280 (248 if the modulus skips its leading zero byte).
        assertTrue(der.size in 248..249, "identity key DER is ${der.size} bytes")
        assertEquals(0x30, der[0].toInt() and 0xFF)
        var i = 1
        val seqLen = readLength(der, i).also { i = it.second }.first

        // [1] — u16be key length + the 65-byte uncompressed P-256 signing point
        assertEquals(0x81, der[i].toInt() and 0xFF)
        val len1 = readLength(der, i + 1).also { i = it.second }.first
        val c1 = der.copyOfRange(i, i + len1)
        i += len1
        val pointLen = ((c1[0].toInt() and 0xFF) shl 8) or (c1[1].toInt() and 0xFF)
        assertEquals(65, pointLen)
        assertEquals(0x04, c1[2].toInt() and 0xFF, "signing point is uncompressed")
        assertEquals(67, len1)

        // [2] — u16be key length + RSA PKCS#1 RSAPublicKey DER
        assertEquals(0x82, der[i].toInt() and 0xFF)
        val len2 = readLength(der, i + 1).also { i = it.second }.first
        val c2 = der.copyOfRange(i, i + len2)
        i += len2
        val rsaLen = ((c2[0].toInt() and 0xFF) shl 8) or (c2[1].toInt() and 0xFF)
        assertEquals(len2 - 2, rsaLen)
        assertEquals(0x30, c2[2].toInt() and 0xFF, "encryption key is a PKCS#1 RSAPublicKey")

        assertEquals(seqLen, i - 3, "DER consumed exactly")
    }

    @Test
    fun prekeyDataIsTheCapturedShape() {
        val ts = 1_760_000_000L
        val blob = identity.prekeyData(ts)
        assertEquals(109, blob.size, "prekey blob is ${blob.size} bytes")
        assertEquals(0x0a, blob[0].toInt())
        assertEquals(0x20, blob[1].toInt())
        assertEquals(0x12, blob[34].toInt())
        assertEquals(0x40, blob[35].toInt())
        assertEquals(0x09, blob[100].toInt())
        val timestamp = java.lang.Double.longBitsToDouble(readLe64(blob, 101))
        assertEquals(ts.toDouble(), timestamp)
    }

    @Test
    fun prekeySignatureVerifiesAgainstTheDeviceKey() {
        val ts = 1_760_000_000L
        val blob = identity.prekeyData(ts)
        val x = blob.copyOfRange(2, 34)
        val sig = blob.copyOfRange(36, 100)
        val payload = "NGMPrekeySignature".toByteArray(Charsets.US_ASCII) + x +
            java.lang.Double.longBitsToDouble(readLe64(blob, 101)).let {
                ByteArray(8) { i -> (java.lang.Double.doubleToLongBits(it) ushr (8 * i)).toByte() }
            }
        val verifier = java.security.Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(
            java.security.KeyFactory.getInstance("EC").generatePublic(
                java.security.spec.X509EncodedKeySpec(identity.deviceKey.public.encoded),
            ),
        )
        verifier.update(payload)
        assertTrue(verifier.verify(dev.fenn.imessage.crypto.EcCrypto.rawToDer(sig)))
    }

    @Test
    fun ktLoggableDataIsTheCapturedShape() {
        val blob = identity.ktLoggableData()
        assertEquals(40, blob.size, "kt blob is ${blob.size} bytes")
        assertEquals(0x0a, blob[0].toInt())
        assertEquals(0x22, blob[1].toInt())
        assertEquals(0x0a, blob[2].toInt())
        assertEquals(0x20, blob[3].toInt())
        assertEquals(0x10, blob[36].toInt())
        assertEquals(0x0d, blob[37].toInt(), "ngm-version 13")
        assertEquals(0x18, blob[38].toInt())
        assertEquals(0x05, blob[39].toInt(), "kt-version 5")
    }

    @Test
    fun clientDataCarriesIdentityPlusCapturedStatics() {
        val data = MadridIdentity.clientData(identity, 1_760_000_000L)
        assertTrue(data["public-message-identity-key"] is ByteArray)
        assertEquals(2L, data["public-message-identity-version"])
        assertEquals(1.0, data["ec-version"])
        assertEquals(13L, data["public-message-identity-ngm-version"])
        assertTrue(data["public-message-ngm-device-prekey-data-key"] is ByteArray)
        assertEquals(5L, data["kt-version"])
        assertEquals(true, data["is-c2k-equipment"])
        assertEquals(false, data["prefers-sdr"])
        assertEquals(1.0, data["nicknames-version"])
        assertEquals(52, data.size, "6 identity keys + 47 captured statics, ec-version deduped")
    }

    @Test
    fun serializeRestoreRoundTripsTheIdentity() {
        val restored = MadridIdentity.restore(identity.serialize())
        assertNotNull(restored)
        assertTrue(restored.identityKeyDer().contentEquals(identity.identityKeyDer()))
        assertTrue(restored.ktLoggableData().contentEquals(identity.ktLoggableData()))
    }

    private fun readLength(der: ByteArray, at: Int): Pair<Int, Int> {
        val first = der[at].toInt() and 0xFF
        return if (first < 0x80) first to at + 1
        else {
            val n = first and 0x7F
            var v = 0
            for (k in 1..n) v = (v shl 8) or (der[at + k].toInt() and 0xFF)
            v to at + 1 + n
        }
    }

    private fun readLe64(b: ByteArray, at: Int): Long {
        var v = 0L
        for (k in 7 downTo 0) v = (v shl 8) or (b[at + k].toLong() and 0xFF)
        return v
    }
}
