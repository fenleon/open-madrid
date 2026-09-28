package dev.fenn.imessage.courier

import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature

/**
 * The connect command's auth construction (spec §3.3): device/push token (1), state 1 (2),
 * connection flags (5), the Albert device certificate (12), a nonce (13) and its RSA
 * signature (14), sent in that order.
 *
 * Nonce (§3.3): the two sources agree it is the structured 17-byte nonce of §1.4 with the
 * type byte 0x00 (APNs) — 0x00 ‖ big-endian unix-milliseconds ‖ 8 random bytes — signed
 * *alone*: `0x01 0x01` + RSA-SHA1-PKCS1v1.5 over the raw nonce. The Go client instead sends
 * a 20-byte random nonce with the first byte zeroed ([NonceShape.Random20FirstByteZeroed]);
 * the spec does not arbitrate (C57), so the shape is an explicit parameter defaulting to the
 * section's structured agreement.
 *
 * Port note: in the originating repo the structured nonce and the signature prefix lived in
 * the signing component (not ported into this module); the spec-derived byte shapes it
 * provides (§1.4/§3.3) are inlined below. The certificate comes from the stored activation
 * state and the signature key is the push key the certificate was issued for.
 */
object CourierConnect {

    enum class NonceShape {
        /** §3.3's recorded agreement: the 17-byte §1.4 nonce with the APNs type byte 0x00. */
        Structured17,

        /** Go-only variant (C57): 20 random bytes with the first byte zeroed. */
        Random20FirstByteZeroed,
    }

    /** §1.4 nonce type byte for APNs use. */
    private const val NONCE_TYPE_APNS = 0x00

    /** §1.4/§3.3: every signature is prefixed with the two bytes 0x01 0x01. */
    private val SIGNATURE_PREFIX = byteArrayOf(0x01, 0x01)

    fun nonce(
        shape: NonceShape = NonceShape.Structured17,
        nowMillis: Long = System.currentTimeMillis(),
        random: SecureRandom = SecureRandom(),
    ): ByteArray = when (shape) {
        NonceShape.Structured17 -> structuredNonce(nowMillis, random)
        NonceShape.Random20FirstByteZeroed -> ByteArray(20).also { random.nextBytes(it); it[0] = 0x00 }
    }

    /** §1.4 structured nonce: type byte ‖ 8-byte BE unix-millis ‖ 8 random bytes. */
    private fun structuredNonce(nowMillis: Long, random: SecureRandom): ByteArray {
        val tail = ByteArray(8).also(random::nextBytes)
        val millis = ByteArray(8)
        for (i in 0 until 8) millis[i] = (nowMillis ushr (8 * (7 - i))).toByte()
        return byteArrayOf(NONCE_TYPE_APNS.toByte()) + millis + tail
    }

    /** `0x01 0x01` + RSA-SHA1-PKCS1v1.5 over [nonce] alone (§3.3 — signed alone, no fields). */
    fun signature(pushKey: PrivateKey, nonce: ByteArray): ByteArray {
        val signer = Signature.getInstance("SHA1withRSA")
        signer.initSign(pushKey)
        signer.update(nonce)
        return SIGNATURE_PREFIX + signer.sign()
    }

    /**
     * The connect frame's fields in the recorded order (§3.3). [flags] starts from
     * [CourierCommands.CONNECT_FLAGS_BASE]; the Go-only root bit ([CourierCommands]
     * .CONNECT_FLAG_ROOT, C57) is added by the caller. [includeRustVersionField] appends the
     * Rust-only field 0x10 = 9 (C57) — its position is unrecorded, so it goes last; fields
     * are id-tagged, so order only matters for the recorded six.
     */
    fun connectFrame(
        deviceToken: ByteArray,
        pushCertificateDer: ByteArray,
        nonce: ByteArray,
        signature: ByteArray,
        flags: Int = CourierCommands.CONNECT_FLAGS_BASE,
        includeRustVersionField: Boolean = false,
    ): CourierFrame.Frame {
        require(flags and CourierCommands.CONNECT_FLAGS_BASE == CourierCommands.CONNECT_FLAGS_BASE) {
            "flags ${flags.toString(2)} lack the base 0x41 (spec §3.3)"
        }
        val fields = listOf(
            CourierFrame.Frame.Field(CourierCommands.CONNECT_FIELD_TOKEN, deviceToken),
            CourierFrame.Frame.Field(
                CourierCommands.CONNECT_FIELD_STATE,
                byteArrayOf(CourierCommands.CONNECT_STATE.toByte()),
            ),
            CourierFrame.Frame.Field(CourierCommands.CONNECT_FIELD_FLAGS, byteArrayOf(flags.toByte())),
            CourierFrame.Frame.Field(CourierCommands.CONNECT_FIELD_CERTIFICATE, pushCertificateDer),
            CourierFrame.Frame.Field(CourierCommands.CONNECT_FIELD_NONCE, nonce),
            CourierFrame.Frame.Field(CourierCommands.CONNECT_FIELD_SIGNATURE, signature),
        )
        val withExtra = if (includeRustVersionField) {
            fields + CourierFrame.Frame.Field(
                CourierCommands.CONNECT_FIELD_RUST_VERSION,
                byteArrayOf(CourierCommands.CONNECT_RUST_VERSION_VALUE.toByte()),
            )
        } else {
            fields
        }
        return CourierFrame.Frame(CourierFrame.CONNECT, withExtra)
    }
}
