package dev.fenn.imessage.registration

import dev.fenn.imessage.crypto.EcCrypto
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64

/**
 * The com.apple.madrid NGM identity carried in the §1.4 register's `client-data`
 * [rustpush:ids/user.rs IDSNGMIdentity]: four keys —
 *
 * - `signing` — EC P-256, the legacy identity signing key (payload signatures);
 * - `encryption` — RSA-1280, the legacy identity encryption key (payload decryption);
 * - `deviceKey` — EC P-256, the NGM device identity key (`kt-loggable-data`, KT gossip);
 * - `preKey` — EC P-256, the NGM device prekey (`public-message-ngm-device-prekey-data-key`).
 *
 * The identity is created once and persisted across registers — peers encrypt to its public
 * keys via lookups, so a rotating identity strands conversations (same shape as the push
 * identity's persistence, [rustpush:identity.save/restore]).
 */
class MadridIdentity(
    val signing: KeyPair,
    val encryption: KeyPair,
    val deviceKey: KeyPair,
    val preKey: KeyPair,
) {

    /**
     * The `public-message-identity-key` blob [rustpush:IDSUserIdentity.encode]: a DER
     * SEQUENCE of two context-tagged primitive OCTET STRINGs, each content-prefixed with the
     * u16 big-endian key length — [1] the 65-byte uncompressed P-256 signing point, [2] the
     * RSA PKCS#1 public-key DER of the encryption key. 249 bytes at RSA-1280.
     */
    fun identityKeyDer(): ByteArray {
        val signingPub = signing.public as ECPublicKey
        val w = signingPub.w
        val point = byteArrayOf(0x04) + fixed32(w.affineX) + fixed32(w.affineY)
        val enc1 = u16be(point.size) + point
        val rsa = rsaPkcs1PublicDer(encryption.public as RSAPublicKey)
        val enc2 = u16be(rsa.size) + rsa
        return derSequence(derContextPrimitive(1, enc1) + derContextPrimitive(2, enc2))
    }

    /**
     * The `public-message-ngm-device-prekey-data-key` blob [rustpush:build_prekey_data] —
     * protobuf `PreKeyData`: the prekey's x-coordinate (32 B), the device key's ECDSA-SHA256
     * raw signature over `"NGMPrekeySignature" ‖ x ‖ f64-le timestamp`, and the timestamp.
     * 109 bytes.
     */
    fun prekeyData(epochSeconds: Long): ByteArray {
        val x = xOnly(preKey.public as ECPublicKey)
        val seconds = epochSeconds.toDouble()
        val payload = "NGMPrekeySignature".toByteArray(Charsets.US_ASCII) + x +
            seconds.toRawBits().let { b ->
                val out = ByteArray(8)
                for (i in 0 until 8) out[i] = (b ushr (8 * i)).toByte()
                out
            }
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(deviceKey.private)
        sig.update(payload)
        val raw = EcCrypto.derToRaw(sig.sign())
        return protoBytes(1, x) + protoBytes(2, raw) + byteArrayOf(0x09) + fixed64le(seconds.toRawBits())
    }

    /**
     * The `kt-loggable-data` blob [rustpush:KtLoggableData] — protobuf: the NGM device
     * identity's x-coordinate, ngm-version 13, kt-version 5. 40 bytes.
     */
    fun ktLoggableData(): ByteArray {
        val inner = protoBytes(1, xOnly(deviceKey.public as ECPublicKey))
        return protoBytes(1, inner) + byteArrayOf(0x10, 0x0d, 0x18, 0x05)
    }

    /** Persisted form — per key pair: PKCS#8 private + X.509 public, base64, colon-joined. */
    fun serialize(): String = listOf(
        signing.private.encoded, signing.public.encoded,
        encryption.private.encoded, encryption.public.encoded,
        deviceKey.private.encoded, deviceKey.public.encoded,
        preKey.private.encoded, preKey.public.encoded,
    ).joinToString(":") { b64(it) }

    companion object {
        /** The static capability half of the madrid `client-data` — capture + [rustpush:MADRID_SERVICE]. */
        val CLIENT_DATA: Map<String, Any?> = linkedMapOf(
            "is-c2k-equipment" to true,
            "optionally-receive-typing-indicators" to true,
            "show-peer-errors" to true,
            "supports-ack-v1" to true,
            "supports-activity-sharing-v1" to true,
            "supports-audio-messaging-v2" to true,
            "supports-autoloopvideo-v1" to true,
            "supports-be-v1" to true,
            "supports-ca-v1" to true,
            "supports-fsm-v1" to true,
            "supports-fsm-v2" to true,
            "supports-fsm-v3" to true,
            "supports-ii-v1" to true,
            "supports-impact-v1" to true,
            "supports-inline-attachments" to true,
            "supports-keep-receipts" to true,
            "supports-location-sharing" to true,
            "supports-media-v2" to true,
            "supports-photos-extension-v1" to true,
            "supports-st-v1" to true,
            "supports-update-attachments-v1" to true,
            "supports-people-request-messages" to true,
            "supports-people-request-messages-v2" to true,
            "supports-people-request-messages-v3" to true,
            "supports-rem" to true,
            "nicknames-version" to 1.0,
            "supports-cross-platform-sharing" to true,
            "supports-original-timestamp-v1" to true,
            "supports-sa-v1" to true,
            "supports-photos-extension-v2" to true,
            "prefers-sdr" to false,
            "supports-shared-exp" to true,
            "supports-protobuf-payload-data-v2" to true,
            "supports-hdr" to true,
            "supports-heif" to true,
            "supports-dq-nr" to true,
            "supports-family-invite-message-bubble" to true,
            "supports-live-delivery" to true,
            "supports-findmy-plugin-messages" to true,
            "supports-stick-moji-backs" to true,
            "supports-emoji-tapbacks" to true,
            "supports-send-later-messages" to true,
            "supports-certified-delivery-v1" to true,
            "supports-transcript-backgrounds" to true,
            "supports-gti" to true,
            "supports-polls" to true,
        )

        /**
         * The six identity keys that open every service's `client-data` (§1.4) — no capability
         * keys: the ones beyond these are per service and come from [RegisterServiceCatalog]
         * (madrid's are [CLIENT_DATA]). [ecVersion] is capture-bound per service: madrid sends
         * the REAL 1.0, the other three send the INTEGER 1L — the plist distinguishes them, so
         * this is `Any`.
         */
        fun clientData(
            identity: MadridIdentity,
            prekeyTimestampEpochSeconds: Long,
            ecVersion: Any = 1.0,
        ): Map<String, Any?> = clientData(identity, identity.prekeyData(prekeyTimestampEpochSeconds), ecVersion)

        /**
         * The same dict with a caller-minted [prekeyBlob]. The reference mints the prekey ONCE,
         * outside the service loop, and clones the same bytes into every service's `client-data`
         * (`rustpush/src/ids/user.rs:982`) — every fresh mint is a fresh ECDSA signature, so
         * minting per service would put four different blobs in one body. Callers registering
         * more than one service pass one blob to all of them ([RegisterServiceCatalog.services]).
         */
        fun clientData(
            identity: MadridIdentity,
            prekeyBlob: ByteArray,
            ecVersion: Any = 1.0,
        ): Map<String, Any?> = linkedMapOf(
            "public-message-identity-key" to identity.identityKeyDer(),
            "public-message-identity-version" to 2L,
            "ec-version" to ecVersion,
            "public-message-identity-ngm-version" to 13L,
            "public-message-ngm-device-prekey-data-key" to prekeyBlob,
            "kt-version" to 5L,
        )

        fun generate(): MadridIdentity = MadridIdentity(
            signing = keyPair("EC", 256),
            encryption = keyPair("RSA", 1280),
            deviceKey = keyPair("EC", 256),
            preKey = keyPair("EC", 256),
        )

        fun restore(serialized: String): MadridIdentity? = runCatching {
            val parts = serialized.split(":")
            require(parts.size == 8) { "madrid identity serialization is 8 base64 fields" }
            fun pair(algorithm: String, pkcs8: String, x509: String): KeyPair {
                val factory = KeyFactory.getInstance(algorithm)
                return KeyPair(
                    factory.generatePublic(java.security.spec.X509EncodedKeySpec(Base64.getDecoder().decode(x509))),
                    factory.generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(pkcs8))),
                )
            }
            MadridIdentity(
                signing = pair("EC", parts[0], parts[1]),
                encryption = pair("RSA", parts[2], parts[3]),
                deviceKey = pair("EC", parts[4], parts[5]),
                preKey = pair("EC", parts[6], parts[7]),
            )
        }.getOrNull()

        private fun keyPair(algorithm: String, bits: Int): KeyPair =
            KeyPairGenerator.getInstance(algorithm).apply { initialize(bits) }.generateKeyPair()

        private fun b64(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)

        private fun xOnly(key: ECPublicKey): ByteArray = fixed32(key.w.affineX)

        private fun fixed32(v: BigInteger): ByteArray {
            val raw = v.toByteArray()
            val out = ByteArray(32)
            raw.copyInto(out, maxOf(0, 32 - raw.size), maxOf(0, raw.size - 32))
            return out
        }

        private fun fixed64le(bits: Long): ByteArray {
            val out = ByteArray(8)
            for (i in 0 until 8) out[i] = (bits ushr (8 * i)).toByte()
            return out
        }

        private fun u16be(v: Int) = byteArrayOf((v ushr 8).toByte(), v.toByte())

        /** Minimal DER writer: lengths ≥ 128 take the long form (both our inner blobs do). */
        private fun derLength(len: Int): ByteArray = when {
            len < 0x80 -> byteArrayOf(len.toByte())
            len < 0x100 -> byteArrayOf(0x81.toByte(), len.toByte())
            else -> byteArrayOf(0x82.toByte(), (len ushr 8).toByte(), len.toByte())
        }

        private fun derSequence(content: ByteArray): ByteArray {
            val out = ByteArrayOutputStream()
            out.write(0x30)
            out.write(derLength(content.size))
            out.write(content)
            return out.toByteArray()
        }

        private fun derContextPrimitive(tag: Int, content: ByteArray): ByteArray {
            val out = ByteArrayOutputStream()
            out.write(0x80 or tag)
            out.write(derLength(content.size))
            out.write(content)
            return out.toByteArray()
        }

        /** RSA PKCS#1 RSAPublicKey DER: SEQUENCE(INTEGER modulus, INTEGER publicExponent). */
        private fun rsaPkcs1PublicDer(key: RSAPublicKey): ByteArray {
            val modulus = derInteger(key.modulus)
            val exponent = derInteger(key.publicExponent)
            return derSequence(modulus + exponent)
        }

        private fun derInteger(v: BigInteger): ByteArray {
            val body = v.toByteArray() // two's complement, minimal with sign bit — exactly DER
            val out = ByteArrayOutputStream()
            out.write(0x02)
            out.write(derLength(body.size))
            out.write(body)
            return out.toByteArray()
        }

        private fun protoBytes(field: Int, value: ByteArray): ByteArray {
            val out = ByteArrayOutputStream()
            var key = (field shl 3) or 2
            while (key >= 0x80) {
                out.write((key and 0x7f) or 0x80)
                key = key ushr 7
            }
            out.write(key)
            out.write(derLength(value.size)) // varint == short DER for < 128; our blobs stay small
            out.write(value)
            return out.toByteArray()
        }
    }
}
