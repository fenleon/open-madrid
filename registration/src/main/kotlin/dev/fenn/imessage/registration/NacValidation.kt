package dev.fenn.imessage.registration

/**
 * NAC validation stamp assembly (ValidationCtx::sign / ValidationCtx::key_establishment,
 * open_absinthe::nac, librust_lib_bluebubbles): the deku wire layouts of ValidationBody /
 * ValidationData and the EstablishResponse parse, transcribed from the byte-exact models
 * (nac_mint.py + NAC-NOTES.md). SignState::sign's output arrives as a parameter (sig16) —
 * that sub-step is modeled separately and deliberately not stubbed here.
 */
internal object NacValidation {

    /**
     * validation_body_to_bits: tag 0x05 | u32be(1) | u32be(0x180) | scrambled(384) |
     * u64be(0x4f) | cert(79) = 480 bytes.
     */
    private fun bodyToBits(scrambled: ByteArray, cert: ByteArray): ByteArray {
        require(scrambled.size == 0x180) { "body: scrambled must be 0x180 bytes" }
        require(cert.size == 0x4f) { "body: cert chunk must be 0x4f bytes" }
        val blob = ByteArray(480)
        blob[0] = 0x05
        putU32be(blob, 1, 1)
        putU32be(blob, 5, 0x180)
        scrambled.copyInto(blob, 9)
        putU64be(blob, 9 + 0x180, 0x4f)
        cert.copyInto(blob, 17 + 0x180)
        return blob
    }

    /** validation_data_to_bits: tag 0x02 | rand(16) | sig(16) | u32be(len) | blob(480). */
    private fun dataToBits(rand16: ByteArray, sig16: ByteArray, blob: ByteArray): ByteArray {
        require(rand16.size == 16 && sig16.size == 16) { "data: rand/sig must be 16 bytes" }
        val stamp = ByteArray(37 + blob.size)
        stamp[0] = 0x02
        rand16.copyInto(stamp, 1)
        sig16.copyInto(stamp, 17)
        putU32be(stamp, 33, blob.size)
        blob.copyInto(stamp, 37)
        return stamp
    }

    /** ValidationCtx::sign: the 517-byte validation stamp (sig16 supplied by the caller). */
    internal fun mint(
        cert79: ByteArray,
        session250: ByteArray,
        rngPad130: ByteArray,
        rand16: ByteArray,
        sig16: ByteArray,
    ): ByteArray {
        val scrambled = NacMerge.scrambleBody(session250, rngPad130)
        return dataToBits(rand16, sig16, bodyToBits(scrambled, cert79))
    }

    /**
     * ValidationCtx::key_establishment (0x1792fb0). EstablishResponse wire (698 B live,
     * offsets confirmed against the captures): tag u8 | key16 @1 | u32be bodyLen @0x11 |
     * body @0x15 (0x250 = 592 B live; decrypt_cbc consumes exactly bodyLen bytes) |
     * trailing data Vec (copied verbatim by the binary, unused by the crypto). The iv and
     * body are mapped through SKEY (0x2247f6), decrypted with the established round keys,
     * and the plaintext is mapped through SDAT (0x2246f6). Returns the SDAT-mapped
     * EstablishKeyResponse wire (592 B live; its payload must parse to 0x240 bytes).
     */
    internal fun keyEstablishment(sessionInfo: ByteArray, pearKey16: ByteArray): ByteArray {
        require(pearKey16.size == 16) { "key_establishment: pear key must be 16 bytes" }
        require(sessionInfo.size >= 21) { "key_establishment: truncated EstablishResponse" }
        val key16 = sessionInfo.copyOfRange(1, 17)
        val bodyLen = u32be(sessionInfo, 17)
        require(sessionInfo.size >= 21 + bodyLen) { "key_establishment: body truncated" }
        val rk = PearAes.establishKey(pearKey16)
        val skey = PearTables.skey
        val iv = ByteArray(16) { skey[key16[it].toInt() and 0xff] }
        val ct = ByteArray(bodyLen) { skey[sessionInfo[21 + it].toInt() and 0xff] }
        val pt = PearAes.decryptCbc(ct, iv, rk)
        val sdat = PearTables.sdat
        for (i in pt.indices) pt[i] = sdat[pt[i].toInt() and 0xff]
        return pt
    }

    private fun u32be(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xff) shl 24) or ((b[off + 1].toInt() and 0xff) shl 16) or
            ((b[off + 2].toInt() and 0xff) shl 8) or (b[off + 3].toInt() and 0xff)

    private fun putU32be(b: ByteArray, off: Int, v: Int) {
        b[off] = (v ushr 24).toByte()
        b[off + 1] = (v ushr 16).toByte()
        b[off + 2] = (v ushr 8).toByte()
        b[off + 3] = v.toByte()
    }

    private fun putU64be(b: ByteArray, off: Int, v: Long) {
        for (i in 0 until 8) b[off + i] = (v ushr (56 - 8 * i)).toByte()
    }
}
