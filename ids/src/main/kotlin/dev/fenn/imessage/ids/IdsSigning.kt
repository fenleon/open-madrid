package dev.fenn.imessage.ids

import java.io.ByteArrayOutputStream
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature

/**
 * The signed-request construction of spec §1.4, shared by the register and lookup paths.
 *
 * Nonce: 17 bytes — 1 type byte, an 8-byte big-endian unix-milliseconds timestamp, 8 random
 * bytes. Signing payload: the nonce followed by a big-endian u32 length-prefixed concatenation
 * of the request's fields (bag key string, query string, request body, raw push token).
 * Signature: RSA-SHA1-PKCS1v1.5 over that payload, output prefixed with the two bytes
 * `0x01 0x01` and then base64'd by the caller.
 *
 * Keys are parameters — Android Keystore integration is a later component and is not wired here.
 */
object IdsSigning {

    /** Nonce length in bytes (spec §1.4). */
    const val NONCE_BYTES = 17

    /** Nonce type byte for HTTPS requests (spec §1.4). */
    const val TYPE_HTTPS: Byte = 0x01

    /** Nonce type byte for APNs use (spec §1.4). */
    const val TYPE_APNS: Byte = 0x00

    /** The two bytes every RSA-SHA1 signature output starts with (§1.4/§3.3). */
    val SIGNATURE_PREFIX_BYTES = byteArrayOf(0x01, 0x01)

    fun nonce(
        type: Byte = TYPE_HTTPS,
        nowMillis: Long = System.currentTimeMillis(),
        random: SecureRandom = SecureRandom(),
    ): ByteArray {
        require(type == TYPE_HTTPS || type == TYPE_APNS) {
            "nonce type must be 0x01 (HTTPS) or 0x00 (APNs) — spec §1.4 records only those two"
        }
        val out = ByteArray(NONCE_BYTES)
        out[0] = type
        for (i in 0 until 8) out[1 + i] = (nowMillis ushr ((7 - i) * 8)).toByte()
        val randomBytes = ByteArray(8)
        random.nextBytes(randomBytes)
        randomBytes.copyInto(out, 9)
        return out
    }

    /** The bytes that get signed: [nonce] then each field as u32-length + bytes (spec §1.4). */
    fun signingBytes(nonce: ByteArray, fields: List<ByteArray>): ByteArray {
        require(nonce.size == NONCE_BYTES) { "nonce must be $NONCE_BYTES bytes (spec §1.4), was ${nonce.size}" }
        val out = ByteArrayOutputStream(nonce.size + fields.sumOf { 4 + it.size })
        out.write(nonce)
        for (field in fields) {
            out.write((field.size ushr 24) and 0xFF)
            out.write((field.size ushr 16) and 0xFF)
            out.write((field.size ushr 8) and 0xFF)
            out.write(field.size and 0xFF)
            out.write(field)
        }
        return out.toByteArray()
    }

    /** `0x01 0x01` + RSA-SHA1-PKCS1v1.5 over [signingBytes] — base64 it for the header. */
    fun sign(key: PrivateKey, nonce: ByteArray, fields: List<ByteArray>): ByteArray {
        val signer = Signature.getInstance("SHA1withRSA")
        signer.initSign(key)
        signer.update(signingBytes(nonce, fields))
        return SIGNATURE_PREFIX_BYTES + signer.sign()
    }
}
