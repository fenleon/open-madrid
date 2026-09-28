package dev.fenn.imessage.crypto

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyAgreement

/**
 * The §4.3 "pair-ec" encryption envelope — pure JCE, no third-party crypto, and a
 * hand-rolled minimal protobuf for the outer/inner messages (only varint and
 * length-delimited fields; no protobuf dependency).
 *
 * Wire form (§4.3): an outer protobuf with the ciphertext (field 1), the ephemeral P-256
 * public key (field 2), a 64-byte raw ECDSA-P256-SHA256 signature (field 3), and the
 * 7-byte key validator (field 99). The inner message carries the gzipped-plist plaintext
 * (field 1), a per-sender-pair counter (field 2), and optional key-transparency gossip
 * (field 3) / debug (field 99) fields.
 *
 * Envelope *selection* between this and [PairEnvelope] is unresolved (spec §4.5, §7 item 1,
 * C25) — this codec builds the scheme and invents no selection rule. The sender-side
 * counter *policy* (keying, persistence) is C27-open — rev 12 records both sources
 * persisting from 0 — but the codec takes the counter as a parameter and persists nothing.
 *
 * Not recorded in the spec and therefore explicit (TODO(capture), §7 item 21 / C57):
 * - the ephemeral key's wire form: §4.3's prose records a 33-byte compressed point, the
 *   field-2 extraction records 32 bytes — [EphemeralKeyForm] parameter, defaulting to the
 *   §4.3 prose; a capture arbitrates.
 * - where the Rust side applies the inner-body gzip (C57) — the caller hands this codec
 *   already-gzipped bytes (§4.1 records Go gzipping the plist before encryption).
 */
object PairEcEnvelope {

    /** Validator final version byte — agreed at 0x0c (spec §4.3, second-extraction correction). */
    const val VALIDATOR_VERSION: Byte = 0x0c

    const val VALIDATOR_BYTES = 7 // 2-byte prefix × 3 keys + the version byte

    /** HKDF-SHA256 SALT (§4.3, rev-12 correction) — an interop-required protocol constant; info is EMPTY. */
    const val HKDF_SALT = "LastPawn-MessageKeys"

    const val PREKEY_SIGNATURE_LABEL = "NGMPrekeySignature"

    /** Protobuf field numbers (§4.3, C52 closed by facts-only extraction — recorded, not configurable). */
    object FieldNumbers {
        const val OUTER_PAYLOAD = 1
        const val OUTER_EPHEMERAL_KEY = 2
        const val OUTER_SIGNATURE = 3
        const val OUTER_VALIDATOR = 99
        const val INNER_MESSAGE = 1
        const val INNER_COUNTER = 2
        const val INNER_GOSSIP = 3
        const val INNER_DEBUG = 99
    }

    /**
     * The field-2 ephemeral key's wire form. §4.3's prose records a 33-byte compressed
     * point; the field-2 extraction records 32 bytes (C57, §7 item 21 — capture-bound).
     * [COMPRESSED_33] is the default per the §4.3 wording; the 32-byte form is the bare
     * x-coordinate (the receiver recovers the point by trying both parity prefixes).
     */
    enum class EphemeralKeyForm(val wireBytes: Int) {
        COMPRESSED_33(33),
        X_ONLY_32(32),
    }

    /**
     * Encrypts [plaintext] (the gzipped plist) to [recipientPrekey] (33-byte compressed).
     * The inner message (plaintext ‖ counter ‖ optional gossip/debug) is what gets padded
     * and encrypted — §4.3's "the inner message carries the plaintext …, a counter, and
     * optional key-transparency gossip".
     *
     * The signature covers (shared secret, recipient prekey bytes, sender ephemeral key
     * bytes — the field-2 wire form chosen by [ephemeralKeyForm], recipient device-key
     * bytes, ciphertext); the marshalled key forms are the caller's (§4.3 records the
     * signature items, not their encodings).
     */
    fun encrypt(
        plaintext: ByteArray,
        recipientPrekey: ByteArray,
        recipientPrekeyMarshalled: ByteArray,
        senderDeviceKeyMarshalled: ByteArray,
        recipientDeviceKeyMarshalled: ByteArray,
        counter: Long,
        senderDeviceSigningKey: PrivateKey,
        random: SecureRandom,
        ephemeralKeyForm: EphemeralKeyForm = EphemeralKeyForm.COMPRESSED_33,
        gossip: ByteArray? = null,
        debug: ByteArray? = null,
    ): ByteArray {
        val ephemeral = generateKeyPair(random)
        val sharedSecret = ecdh(ephemeral.private, EcCrypto.decompress(recipientPrekey))
        val okm = Hkdf.expand(Hkdf.extract(HKDF_SALT.toByteArray(Charsets.US_ASCII), sharedSecret), ByteArray(0), 48)
        val key = okm.copyOfRange(0, 32)
        val iv = okm.copyOfRange(32, 48)
        val innerFields = ArrayList<Pair<Int, Any>>(4)
        innerFields.add(FieldNumbers.INNER_MESSAGE to plaintext)
        innerFields.add(FieldNumbers.INNER_COUNTER to counter)
        if (gossip != null) innerFields.add(FieldNumbers.INNER_GOSSIP to gossip)
        if (debug != null) innerFields.add(FieldNumbers.INNER_DEBUG to debug)
        val padded = pad(MiniProto.encode(innerFields), random)
        val ciphertext = PairEnvelope.aesCtr(padded, key, iv)
        val ephemeralWire = ephemeralWireBytes(ephemeral.public, ephemeralKeyForm)
        val signature = signRaw(
            senderDeviceSigningKey,
            sharedSecret + recipientPrekeyMarshalled + ephemeralWire +
                recipientDeviceKeyMarshalled + ciphertext,
        )
        return MiniProto.encode(
            listOf(
                FieldNumbers.OUTER_PAYLOAD to ciphertext,
                FieldNumbers.OUTER_EPHEMERAL_KEY to ephemeralWire,
                FieldNumbers.OUTER_SIGNATURE to signature,
                FieldNumbers.OUTER_VALIDATOR to validator(
                    senderDeviceKeyMarshalled, recipientDeviceKeyMarshalled, recipientPrekeyMarshalled,
                ),
            ),
        )
    }

    /**
     * Decrypts an outer message. Validator and signature verification are skipped unless the
     * corresponding keys are supplied (§4.3: a prekey-signature failure only warns; one
     * source verifies only the validator's first six bytes). The received counter is
     * returned but NOT enforced — receiver-side enforcement is C27-open.
     */
    fun decrypt(
        outer: ByteArray,
        recipientPrekeyPrivate: PrivateKey,
        recipientPrekeyMarshalled: ByteArray,
        recipientDeviceKeyMarshalled: ByteArray,
        senderDeviceKeyMarshalled: ByteArray? = null,
        senderDeviceSigningPublicKey: PublicKey? = null,
    ): Pair<ByteArray, Long> {
        val parsed = MiniProto.decode(outer)
        fun bytes(field: Int): ByteArray = parsed.firstOrNull { it.first == field }?.second as? ByteArray
            ?: throw IllegalArgumentException("outer message without field $field")
        val ciphertext = bytes(FieldNumbers.OUTER_PAYLOAD)
        val ephemeralWire = bytes(FieldNumbers.OUTER_EPHEMERAL_KEY)
        val signature = bytes(FieldNumbers.OUTER_SIGNATURE)
        senderDeviceKeyMarshalled?.let { sender ->
            if (parsed.any { p -> p.first == FieldNumbers.OUTER_VALIDATOR }) {
                val received = bytes(FieldNumbers.OUTER_VALIDATOR)
                val expected = validator(sender, recipientDeviceKeyMarshalled, recipientPrekeyMarshalled)
                if (!expected.contentEquals(received)) {
                    throw PairIntegrityException("key validator mismatch: ${received.toHex()} vs ${expected.toHex()}")
                }
            }
        }
        val ephemeralPublic = ephemeralPublicKey(ephemeralWire)
        val sharedSecret = ecdh(recipientPrekeyPrivate, ephemeralPublic)
        val okm = Hkdf.expand(Hkdf.extract(HKDF_SALT.toByteArray(Charsets.US_ASCII), sharedSecret), ByteArray(0), 48)
        val padded = PairEnvelope.aesCtr(
            ciphertext,
            okm.copyOfRange(0, 32),
            okm.copyOfRange(32, 48),
        )
        senderDeviceSigningPublicKey?.let {
            val verified = runCatching {
                verifyRaw(
                    it,
                    sharedSecret + recipientPrekeyMarshalled + ephemeralWire +
                        recipientDeviceKeyMarshalled + ciphertext,
                    signature,
                )
            }.getOrDefault(false)
            if (!verified) throw PairIntegrityException("signature verification failed")
        }
        val inner = MiniProto.decode(unpad(padded))
        val plaintext = inner.firstOrNull { it.first == FieldNumbers.INNER_MESSAGE }?.second as? ByteArray
            ?: throw IllegalArgumentException("inner message without field ${FieldNumbers.INNER_MESSAGE}")
        val counter = inner.firstOrNull { it.first == FieldNumbers.INNER_COUNTER }?.second as? Long ?: 0L
        return plaintext to counter
    }

    /** The field-2 wire bytes for [publicKey] in [form] (§4.3 prose vs C57's 32-byte reading). */
    fun ephemeralWireBytes(publicKey: PublicKey, form: EphemeralKeyForm): ByteArray {
        val compressed = EcCrypto.compress(publicKey)
        return when (form) {
            EphemeralKeyForm.COMPRESSED_33 -> compressed
            EphemeralKeyForm.X_ONLY_32 -> compressed.copyOfRange(1, 33)
        }
    }

    /** Rebuilds the ephemeral public key from either recorded field-2 wire form. */
    fun ephemeralPublicKey(wire: ByteArray): java.security.interfaces.ECPublicKey = when (wire.size) {
        EphemeralKeyForm.COMPRESSED_33.wireBytes -> EcCrypto.decompress(wire)
        EphemeralKeyForm.X_ONLY_32.wireBytes -> EcCrypto.decompressXOnly(wire)
        else -> throw IllegalArgumentException("ephemeral key is ${wire.size} bytes; neither recorded form")
    }

    /** The 7-byte validator: 2-byte prefixes of (sender device, recipient device, recipient prekey) + 0x0c. */
    fun validator(
        senderDeviceKeyMarshalled: ByteArray,
        recipientDeviceKeyMarshalled: ByteArray,
        recipientPrekeyMarshalled: ByteArray,
    ): ByteArray = senderDeviceKeyMarshalled.copyOfRange(0, 2) +
        recipientDeviceKeyMarshalled.copyOfRange(0, 2) +
        recipientPrekeyMarshalled.copyOfRange(0, 2) +
        byteArrayOf(VALIDATOR_VERSION)

    /** The signed prekey record's signature input (§4.3): SHA-256 over label ‖ prekey ‖ LE timestamp. */
    fun prekeySignatureBytes(compressedPrekey: ByteArray, timestampSeconds: Double): ByteArray {
        val ts = ByteBuffer.allocate(8).putLong(java.lang.Double.doubleToLongBits(timestampSeconds)).array()
        return MessageDigest.getInstance("SHA-256")
            .digest(PREKEY_SIGNATURE_LABEL.toByteArray(Charsets.US_ASCII) + compressedPrekey + ts.reversedArray())
    }

    /** Signs the prekey record (§4.3) with the device key; raw 64-byte output. */
    fun signPrekey(deviceKey: PrivateKey, compressedPrekey: ByteArray, timestampSeconds: Double): ByteArray =
        signRaw(deviceKey, prekeySignatureBytes(compressedPrekey, timestampSeconds))

    fun verifyPrekey(
        deviceKey: PublicKey,
        compressedPrekey: ByteArray,
        timestampSeconds: Double,
        signature: ByteArray,
    ): Boolean = runCatching {
        verifyRaw(deviceKey, prekeySignatureBytes(compressedPrekey, timestampSeconds), signature)
    }.getOrDefault(false)

    /** Plaintext ‖ random pad to a 16-byte multiple ‖ 4-byte LE pad length (§4.3). */
    internal fun pad(plaintext: ByteArray, random: SecureRandom): ByteArray {
        val padLength = (16 - plaintext.size % 16) % 16
        val pad = ByteArray(padLength).also { random.nextBytes(it) }
        return plaintext + pad + ByteBuffer.allocate(4).putInt(padLength).array()
    }

    internal fun unpad(padded: ByteArray): ByteArray {
        if (padded.size < 4) throw IllegalArgumentException("padded plaintext too short")
        // plaintext ‖ pad ‖ trailer: body+pad is the 16-byte multiple, the trailer sits outside it.
        if ((padded.size - 4) % 16 != 0) {
            throw IllegalArgumentException("encrypted length ${padded.size} inconsistent with pad-to-16 + 4-byte trailer")
        }
        val padLength = ByteBuffer.wrap(padded.copyOfRange(padded.size - 4, padded.size)).int
        val bodyLength = padded.size - 4 - padLength
        if (bodyLength < 0) throw IllegalArgumentException("padding length $padLength inconsistent with ${padded.size} B input")
        return padded.copyOfRange(0, bodyLength)
    }

    private fun generateKeyPair(random: SecureRandom): KeyPair =
        KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"), random)
        }.generateKeyPair()

    private fun ecdh(privateKey: PrivateKey, publicKey: ECPublicKey): ByteArray {
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(privateKey)
        agreement.doPhase(publicKey, true)
        return agreement.generateSecret()
    }

    private fun signRaw(key: PrivateKey, data: ByteArray): ByteArray {
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(key)
        signer.update(data)
        return EcCrypto.derToRaw(signer.sign())
    }

    private fun verifyRaw(key: PublicKey, data: ByteArray, rawSignature: ByteArray): Boolean {
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(key)
        verifier.update(data)
        return verifier.verify(EcCrypto.rawToDer(rawSignature))
    }

    class PairIntegrityException(message: String) : IllegalStateException(message)

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }
}

/**
 * Minimal protobuf wire codec — varint (wire type 0) and length-delimited (wire type 2)
 * fields only, which is all the §4.3 messages use. Hand-rolled per the task's no-protobuf-
 * library constraint; groups, fixed-width scalars and packed repeated fields do not decode.
 */
internal object MiniProto {

    fun encode(fields: List<Pair<Int, Any>>): ByteArray {
        val out = ByteArrayOutputStream()
        for ((field, value) in fields) {
            when (value) {
                is Long -> {
                    writeVarint(out, ((field shl 3) or 0).toLong())
                    writeVarint(out, value)
                }
                is ByteArray -> {
                    writeVarint(out, ((field shl 3) or 2).toLong())
                    writeVarint(out, value.size.toLong())
                    out.write(value)
                }
                else -> throw IllegalArgumentException("unsupported protobuf value: ${value::class.java.name}")
            }
        }
        return out.toByteArray()
    }

    /** Returns the fields in wire order; varints as [Long], length-delimited as [ByteArray]. */
    fun decode(bytes: ByteArray): List<Pair<Int, Any>> {
        val out = ArrayList<Pair<Int, Any>>()
        var i = 0
        while (i < bytes.size) {
            val (tag, next) = readVarint(bytes, i)
            i = next
            val field = (tag ushr 3).toInt()
            require(field > 0) { "protobuf field number 0" }
            when (val wire = (tag and 0x7).toInt()) {
                0 -> {
                    val (v, next2) = readVarint(bytes, i)
                    i = next2
                    out.add(field to v)
                }
                2 -> {
                    val (len, next2) = readVarint(bytes, i)
                    i = next2
                    if (len > bytes.size - i) throw IllegalArgumentException("length-delimited field overruns input")
                    out.add(field to bytes.copyOfRange(i, i + len.toInt()))
                    i += len.toInt()
                }
                else -> throw IllegalArgumentException("unsupported protobuf wire type $wire")
            }
        }
        return out
    }

    private fun writeVarint(out: ByteArrayOutputStream, v: Long) {
        var value = v
        while (true) {
            if (value and 0x7FL.inv() == 0L) {
                out.write(value.toInt())
                return
            }
            out.write(((value and 0x7F) or 0x80).toInt())
            value = value ushr 7
        }
    }

    private fun readVarint(bytes: ByteArray, at: Int): Pair<Long, Int> {
        var value = 0L
        var shift = 0
        var i = at
        while (true) {
            if (i >= bytes.size) throw IllegalArgumentException("truncated varint")
            if (shift >= 64) throw IllegalArgumentException("varint too long")
            value = value or ((bytes[i].toLong() and 0x7F) shl shift)
            if (bytes[i].toInt() and 0x80 == 0) return value to i + 1
            shift += 7
            i++
        }
    }
}
