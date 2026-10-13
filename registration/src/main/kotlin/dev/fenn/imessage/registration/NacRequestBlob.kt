package dev.fenn.imessage.registration

import java.security.PublicKey
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The §1.1 step-2 `session-info-request` blob (C56-a — the 338-B request the client sends
 * with the step-1 certificate's public key wrapped inside). Field map pinned 2026-10-12 by
 * direct in-process replay of `ValidationCtx::new` (two independent runs, byte-verified;
 * NAC-NOTES.md "Session-24 continuation" + spec §1.1 rev 35):
 *
 * ```
 * blob 338 B = header `01 08 4b2c91481d9b7da0`                                  (10 B, constant)
 *   ‖ RSA-2048-OAEP-SHA1(step-1 cert pubkey, pearKey16 ‖ hmacKey20)             (256 B)
 *   ‖ slot16 (16 fresh client RNG bytes)                                        (16 B)
 *   ‖ u32be(32) — the next field's length marker                                (4 B)
 *   ‖ field32 = blobFieldMap[PearAes.encryptCbc(plain32, iv16, PearAes.initKey(pearKey16))]
 *                                                                               (32 B)
 *
 * `iv16 = blobFieldMap⁻¹(slot16)` — the pear-AES IV is never drawn or carried; the server
 * recomputes it from the wire slot through the inverse of the same substitution table
 * (pinned 2026-10-13 on the c56j replay dumps: `ecbc_arg_r8 == blobFieldMap⁻¹[blob[266:282]]`
 * exactly; an independent IV draw is the 5080/EM residue — spec §1.1 rev 42).
 *   ‖ HMAC-SHA1(hmacKey20, field32)                                             (20 B)
 * ```
 *
 * `plain32 = blobPayloadMap[02 ‖ u32be(1) ‖ innerKey16 ‖ zeros(10)]` — the wire format the
 * binary's serializer writes (`u8 tag=2, u32be version=1, key16`), zero-padded to the 32-B
 * pear-AES block pair and then byte-mapped through the payload table. `blobFieldMap` /
 * `blobPayloadMap` are the .so's byte→byte substitution tables at 0x2249f9 / 0x224af9 (the
 * serializer and the post-encrypt loops apply `table[byte]`, not XOR).
 *
 * Role model: the server decrypts the OAEP → (pearKey16, hmacKey20), derives the PAESKey
 * from pearKey16, decrypts field32, and verifies the HMAC — a possession-of-pearKey16 proof
 * bound to the blob. Everything is minted locally: three fresh RNG draws plus the caller's
 * pearKey16 (the SAME pearKey16 the §1.1 key establishment consumes — [NacMint.keyEstablishmentFull]).
 */
object NacRequestBlob {

    /** The constant 10-byte header every observed blob starts with. */
    val header: ByteArray = byteArrayOf(
        0x01.toByte(), 0x08, 0x4b.toByte(), 0x2c.toByte(), (0x91).toByte(),
        0x48, 0x1d.toByte(), (0x9b).toByte(), 0x7d.toByte(), (0xa0).toByte(),
    )

    const val BLOB_BYTES = 338
    const val PEAR_KEY16_BYTES = 16

    /** Builds the blob; [pearKey16] is returned-consumed by the §1.1 key establishment. */
    fun build(certDer: ByteArray, pearKey16: ByteArray, random: SecureRandom): ByteArray {
        val certificate = java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(certDer.inputStream())
        return build(certificate.publicKey, pearKey16, random)
    }

    fun build(publicKey: PublicKey, pearKey16: ByteArray, random: SecureRandom): ByteArray =
        build(publicKey, pearKey16) { n -> ByteArray(n).also(random::nextBytes) }

    /** Deterministic core (tests): every randomness draw routes through [draw]. */
    internal fun build(publicKey: PublicKey, pearKey16: ByteArray, draw: (Int) -> ByteArray): ByteArray {
        require(pearKey16.size == PEAR_KEY16_BYTES) {
            "pearKey16 must be $PEAR_KEY16_BYTES bytes (got ${pearKey16.size})"
        }
        val hmacKey20 = draw(20)
        val innerKey16 = draw(16)
        val slot16 = draw(16)
        val fieldMap = PearTables.blobFieldMap
        val fieldInv = ByteArray(256).also { inv ->
            for (i in 0 until 256) inv[fieldMap[i].toInt() and 0xff] = i.toByte()
        }
        val iv16 = ByteArray(16) { fieldInv[slot16[it].toInt() and 0xff] }

        val paesKey = PearAes.initKey(pearKey16)
        val plain32 = ByteArray(32)
        plain32[0] = 0x02
        plain32[4] = 0x01 // u32be(1) — the serializer's version field
        innerKey16.copyInto(plain32, W16_OFFSET)
        val payloadMap = PearTables.blobPayloadMap
        val mappedPlain = ByteArray(32) { i -> payloadMap[plain32[i].toInt() and 0xff] }
        val enc32 = PearAes.encryptCbc(mappedPlain, iv16, paesKey)
        val field32 = ByteArray(32) { i -> fieldMap[enc32[i].toInt() and 0xff] }

        val oaep = Cipher.getInstance(OAEP_TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, publicKey)
        }
        val oaepOut = oaep.doFinal(pearKey16 + hmacKey20)
        check(oaepOut.size == 256) { "OAEP output ${oaepOut.size} B, expected 256" }

        val mac = Mac.getInstance("HmacSHA1").apply {
            init(SecretKeySpec(hmacKey20, "HmacSHA1"))
        }
        val tail = mac.doFinal(field32)

        val blob = ByteArray(BLOB_BYTES)
        header.copyInto(blob, 0)
        oaepOut.copyInto(blob, 10)
        slot16.copyInto(blob, 266)
        blob[282] = 0x00
        blob[283] = 0x00
        blob[284] = 0x00
        blob[285] = 0x20 // u32be(32) — the field32 length marker
        field32.copyInto(blob, 286)
        tail.copyInto(blob, 318)
        return blob
    }

    private const val W16_OFFSET = 5
    private const val OAEP_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding"
}
