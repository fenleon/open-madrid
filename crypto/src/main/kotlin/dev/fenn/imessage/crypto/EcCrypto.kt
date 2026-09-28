package dev.fenn.imessage.crypto

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.EllipticCurve
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * JCE-only helpers shared by the §4.2/§4.3 encryptors: P-256 point (de)compression, raw
 * (r‖s) ECDSA signatures, and HKDF-SHA256. No third-party crypto dependency.
 */
object EcCrypto {

    private val P = BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
    private val THREE = BigInteger.valueOf(3)
    private val B = BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
    private val N = BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
    private val G = ECPoint(
        BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
        BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
    )
    private val SQRT_EXPONENT = P.add(BigInteger.ONE).shiftRight(2) // p ≡ 3 (mod 4)

    /** (x, y) of the generator point as a JCE parameter spec (curve params are fixed for P-256). */
    private val P256_SPEC = ECParameterSpec(
        EllipticCurve(ECFieldFp(P), THREE.negate().mod(P), B), // a = -3 mod p
        G,
        N,
        1,
    )

    /** 33-byte compressed SEC1 encoding (0x02/0x03 prefix) of an uncompressed EC public key. */
    fun compress(publicKey: PublicKey): ByteArray {
        val w = (publicKey as ECPublicKey).w
        val x = fixed32(w.affineX)
        val y = fixed32(w.affineY)
        val out = ByteArray(33)
        out[0] = if (y[31].toInt() and 1 == 1) 0x03 else 0x02
        x.copyInto(out, 1)
        return out
    }

    /** Rebuilds an [ECPublicKey] from a 33-byte compressed SEC1 point (decompresses y). */
    fun decompress(compressed: ByteArray): ECPublicKey {
        require(compressed.size == 33) { "compressed P-256 point must be 33 bytes, was ${compressed.size}" }
        val prefix = compressed[0].toInt() and 0xFF
        require(prefix == 0x02 || prefix == 0x03) { "bad compressed point prefix 0x%02x".format(prefix) }
        val x = BigInteger(1, compressed.copyOfRange(1, 33))
        require(x.signum() >= 0 && x < P) { "compressed point x out of range" }
        val rhs = x.modPow(THREE, P).subtract(THREE.multiply(x)).add(B).mod(P)
        var y = rhs.modPow(SQRT_EXPONENT, P)
        if (y.modPow(BigInteger.TWO, P) != rhs) {
            throw IllegalArgumentException("compressed point is not on the P-256 curve")
        }
        if ((y.testBit(0) != (prefix == 0x03))) y = P.subtract(y)
        val spec = KeyFactory.getInstance("EC")
        return spec.generatePublic(ECPublicKeySpec(ECPoint(x, y), P256_SPEC)) as ECPublicKey
    }

    /**
     * Rebuilds an [ECPublicKey] from a 32-byte x-coordinate (the C57 pair-ec field-2 form,
     * which drops the parity prefix): tries both parity prefixes since the wire carries
     * neither.
     */
    fun decompressXOnly(x: ByteArray): ECPublicKey {
        require(x.size == 32) { "x-coordinate must be 32 bytes, was ${x.size}" }
        runCatching { return decompress(byteArrayOf(0x02) + x) }
        return decompress(byteArrayOf(0x03) + x)
    }

    private fun fixed32(v: BigInteger): ByteArray {
        val raw = v.toByteArray()
        val out = ByteArray(32)
        raw.copyInto(out, maxOf(0, 32 - raw.size), maxOf(0, raw.size - 32))
        return out
    }

    /** DER (Java's `SHA256withECDSA` output) → raw 64-byte r‖s. */
    fun derToRaw(der: ByteArray): ByteArray {
        var i = 0
        fun u8(): Int = der[i++].toInt() and 0xFF
        require(u8() == 0x30) { "not a DER ECDSA signature" }
        readDerLength(der, i).let { (len, next) -> i = next + len }
        i = 2
        val r = readDerInteger(der, i)
        i = r.second
        val s = readDerInteger(der, i).first
        return fixed32(r.first) + fixed32(s)
    }

    /** Raw 64-byte r‖s → DER (what Java's `SHA256withECDSA` verify expects). */
    fun rawToDer(raw: ByteArray): ByteArray {
        require(raw.size == 64) { "raw P-256 signature must be 64 bytes, was ${raw.size}" }
        val r = BigInteger(1, raw.copyOfRange(0, 32))
        val s = BigInteger(1, raw.copyOfRange(32, 64))
        val rBytes = derIntegerBody(r)
        val sBytes = derIntegerBody(s)
        return byteArrayOf(0x30, (rBytes.size + sBytes.size).toByte()) + rBytes + sBytes
    }

    private fun readDerInteger(der: ByteArray, at: Int): Pair<BigInteger, Int> {
        require(der[at].toInt() and 0xFF == 0x02) { "bad DER integer at $at" }
        val (len, body) = readDerLength(der, at + 1)
        return BigInteger(1, der.copyOfRange(body, body + len)) to body + len
    }

    private fun derIntegerBody(v: BigInteger): ByteArray {
        var body = v.toByteArray()
        if (body.size > 1 && body[0] == 0.toByte() && body[1].toInt() >= 0) body = body.copyOfRange(1, body.size)
        return byteArrayOf(0x02, body.size.toByte()) + body
    }

    private fun readDerLength(der: ByteArray, at: Int): Pair<Int, Int> {
        val first = der[at].toInt() and 0xFF
        return if (first < 0x80) first to at + 1
        else {
            val n = first and 0x7F
            var len = 0
            for (i in 0 until n) len = (len shl 8) or (der[at + 1 + i].toInt() and 0xFF)
            len to at + 1 + n
        }
    }
}

/** HKDF-SHA256 (RFC 5869) via JCE HMAC — the §4.3 key-derivation primitive. */
object Hkdf {

    fun extract(salt: ByteArray?, ikm: ByteArray): ByteArray =
        hmac(if (salt == null || salt.isEmpty()) ByteArray(32) else salt, ikm)

    fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length <= 255 * 32) { "HKDF output too long" }
        val out = ByteArrayOutputStream(length)
        var t = ByteArray(0)
        var counter = 1
        while (out.size() < length) {
            t = hmac(prk, t + info + byteArrayOf(counter.toByte()))
            out.write(t)
            counter++
        }
        return out.toByteArray().copyOf(length)
    }

    fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }
}
