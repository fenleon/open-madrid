package dev.fenn.imessage.registration

/**
 * Wire framing of the ClearADI provisioning exchange — the deku reads/writes around the
 * already-ported ciphers ([ClearAdiProvision]). Ground truth: `ProvisioningSession::new`
 * (0x17eebf0, new.asm) and `finish` (0x17f1e20, finish.asm) of librust_lib_bluebubbles;
 * report at /tmp/clearadi-re/analysis/provisioning.md §6–§7. Every field the asm does not
 * pin is named by role with its call site cited, never guessed.
 */

/** The Spim byte stream did not match the shape `new()`'s deku reader accepts (0x17eec98). */
class SpimFormatException(message: String) : Exception(message)

/**
 * The parsed Spim (start-provisioning `Response.spim`, base64 on the wire).
 *
 * Wire shape (proven from the asm and pinned against the live library):
 * `field1` — u32 BE ([new.asm] 17eeca4; role unrecorded, reader position 4);
 * `payloadLength` — u32 BE (17eed81) — the deku `ByteSize` limit of the payload Vec (17eeded);
 * `payload` — the next [payloadLength] bytes; the reader rejects a payload of ≤ 59 bytes
 * (17efb33, `cmp …,0x3b`) and feeds the 240-byte payload to [ClearAdiProvision.initSession]
 * (17efb82).
 *
 * The asm continues with trailing reads ([T;N] 17eee41, `read_bytes_const` 17eeecd — the
 * 0x20 size setup is at 17ef00b — and two u32 reads 17ef05f/17ef3e8). The live capture
 * (session 19f) shows a real Spim carrying **99 trailing bytes** that parses fine — the
 * earlier "≤ 23 leftover" pin (error 0x41) was an artifact of the probe harness, not the
 * reader. The trailing bytes are server material the client relays verbatim into the Cpim
 * wire tail (see [Cpim]) and their leading words feed the encrypt IV selection pool.
 */
data class Spim(
    val field1: Int,
    val payloadLength: Int,
    val payload: ByteArray,
    val trailing: ByteArray,
) {
    companion object {
        /** Minimum reader requirement (`cmp rdx,0x3; ja` 17eec6c): the first u32 must fit. */
        private const val MIN_LEN = 4
        /** `cmp QWORD PTR […],0x3b; ja` 17efb33 — the payload Vec must exceed 59 bytes. */
        private const val MIN_PAYLOAD = 60

        fun parse(bytes: ByteArray): Spim {
            if (bytes.size < MIN_LEN) throw SpimFormatException("spim shorter than the first u32 (${bytes.size} B)")
            val field1 = beU32(bytes, 0)
            if (bytes.size < 8) throw SpimFormatException("spim ends before the ByteSize u32")
            val payloadLength = beU32(bytes, 4)
            if (8 + payloadLength > bytes.size) {
                throw SpimFormatException("spim payload Vec needs $payloadLength B, ${bytes.size - 8} available")
            }
            if (payloadLength < MIN_PAYLOAD) {
                throw SpimFormatException("spim payload of $payloadLength B rejected (must exceed 59 B, 17efb33)")
            }
            val payload = bytes.copyOfRange(8, 8 + payloadLength)
            val trailing = bytes.copyOfRange(8 + payloadLength, bytes.size)
            return Spim(field1, payloadLength, payload, trailing)
        }

        private fun beU32(b: ByteArray, off: Int): Int =
            ((b[off].toInt() and 0xff) shl 24) or ((b[off + 1].toInt() and 0xff) shl 16) or
                ((b[off + 2].toInt() and 0xff) shl 8) or (b[off + 3].toInt() and 0xff)
    }
}

/**
 * The random material `new()` pulls (thread_rng, 17ef8d1–17efac9): 32 + 32 + 60 bytes.
 * Injected so Cpim builds are reproducible in tests; production supplies a secure RNG.
 */
fun interface ClearAdiRng {
    /** [n] fresh random bytes (called with 32, 32, 60 in that order — keep draws independent). */
    fun draw(n: Int): ByteArray
}

/**
 * The Cpim wire tail — the 92 bytes after `[u32 BE 5][iv][u32 BE len][encout]` in the outer
 * message (live capture, session 19f: `cap_wiravec.bin`). Shape: `[X 32][u32 BE 52][u32 BE 4]
 * [Y 52]`, where the `[52][4][Y52]` group == the Spim's trailing[16:76] relayed verbatim
 * (server material) and **X (32 B) is not yet source-pinned** — TODO(live-capture) with a
 * second wire sample. The earlier §6 reading (two 256-bit sig/sha fields) is falsified: the
 * `spim_map_signature` output and the SHA-256 digest appear nowhere in the captured wire.
 * Tests seal deterministically; production wires in once X is named.
 */
fun interface CpimTailSeal {
    /**
     * Returns the 92-byte wire tail. [spimTrailing] is the Spim's trailing byte block (the
     * relayed `[52][4][Y52]` group comes from its bytes 16..76), [encryptedPayload] the
     * `encrypt(sessionCtx, iv, plaintext)` output and [iv] the encrypt IV.
     */
    fun seal(spimTrailing: ByteArray, encryptedPayload: ByteArray, iv: ByteArray): ByteArray
}

/**
 * The Cpim wire message (`request.cpim`, base64) — live-pinned from the session-19f capture
 * (`cap_wiravec.bin`, 276 B; the earlier §6 208-B reading is superseded):
 *
 * `[u32 BE 5][iv 16][u32 BE 160][encout 160][CpimTailSeal 92]`
 *
 * `encout = encrypt(sessionCtx, iv, plaintext)` (17f090e), plaintext 160 B =
 * `[u32 BE 32][vec1 32][u32 BE 32][vec2 32][blob 60][gsaArg u64 BE][ts u32 BE][u32 BE 1][tail 12]`:
 * - vec1 = [ClearAdiProvision.encsec] of draw2 (the sealed client secret)
 * - vec2 = draw1 raw — the 32-B gate material echoed back by the server's PTM
 * - blob = the caller's ≤ 60-byte `extra` padded with draw3 (draw3 = the machine `mid`)
 * - gsaArg = −2 (omnisette reference), wire `FF FF FF FF FF FF FF FE` — CONFIRMED live
 * - ts = unix seconds (live: 0x6ac64ac3 ≈ provisioning wall clock)
 * - the trailing `u32 BE 1` + 12 bytes are live-pinned in position; the 12 bytes' source is
 *   TODO(live-capture) (modeled as RNG here)
 * - iv = 16 RNG bytes (17f0782–17f0888 draw them from the thread RNG pool — the earlier
 *   "IV assembled from the Spim's trailing fields" reading was the RNG pool, not the Spim)
 */
data class CpimBuilt(
    /** The full wire message — base64 it into `request.cpim`. */
    val wire: ByteArray,
    /** RNG draw 1 — the 32-B gate material the server's PTM must echo (decrypt out[408:440]). */
    val draw1: ByteArray,
    /** RNG draw 2 — becomes `client_secret`. */
    val draw2: ByteArray,
    /** RNG draw 3 (60 B) — becomes the machine `mid`. */
    val draw3: ByteArray,
    /** The 16-B encrypt IV, echoed in the clear at wire[4:20]. */
    val iv: ByteArray,
)

object Cpim {

    /** `extra` must fit the fixed 60-byte blob slot (`cmp rdx,0x3d; jae` → error, 17efb17). */
    const val MAX_EXTRA = 60
    private const val BLOB_LEN = 60

    fun build(
        rng: ClearAdiRng,
        extra: ByteArray,
        gsaArg: Long,
        nowSeconds: Long,
        sessionCtx: ByteArray,
        payload240: ByteArray,
        spimTrailing: ByteArray,
        tail: CpimTailSeal,
    ): CpimBuilt {
        require(extra.size <= MAX_EXTRA) { "extra blob of ${extra.size} B exceeds the 60 B Cpim slot (17efb17)" }
        val draw1 = rng.draw(32)
        val draw2 = rng.draw(32)
        val draw3 = rng.draw(60)
        val iv = rng.draw(16)
        val vec1 = ClearAdiProvision.encsec(draw2)
        val blob = extra + draw3.copyOfRange(extra.size, BLOB_LEN)

        val plain = ByteArray(4 + 32 + 4 + 32 + BLOB_LEN + 8 + 4 + 4 + 12)
        var p = 0
        p = putBeU32(plain, p, 32)
        System.arraycopy(vec1, 0, plain, p, vec1.size); p += vec1.size
        p = putBeU32(plain, p, 32)
        System.arraycopy(draw1, 0, plain, p, draw1.size); p += draw1.size
        System.arraycopy(blob, 0, plain, p, blob.size); p += blob.size
        p = putBeU64(plain, p, gsaArg)
        p = putBeU32(plain, p, (nowSeconds and 0xffffffffL).toInt())
        p = putBeU32(plain, p, 1)
        System.arraycopy(rng.draw(12), 0, plain, p, 12); p += 12
        require(p == plain.size)

        val encrypted = ClearAdiProvision.encrypt(sessionCtx, iv, plain)
        require(encrypted.size == plain.size)
        val wire = ByteArray(4 + 16 + 4 + encrypted.size + 92)
        var q = 0
        q = putBeU32(wire, q, 5)
        System.arraycopy(iv, 0, wire, q, iv.size); q += iv.size
        q = putBeU32(wire, q, encrypted.size)
        System.arraycopy(encrypted, 0, wire, q, encrypted.size); q += encrypted.size
        System.arraycopy(tail.seal(spimTrailing, encrypted, iv), 0, wire, q, 92); q += 92
        require(q == wire.size)
        return CpimBuilt(wire, draw1, draw2, draw3, iv)
    }

    private fun putBeU32(b: ByteArray, off: Int, v: Int): Int {
        b[off] = (v ushr 24).toByte(); b[off + 1] = (v ushr 16).toByte()
        b[off + 2] = (v ushr 8).toByte(); b[off + 3] = v.toByte()
        return off + 4
    }

    private fun putBeU64(b: ByteArray, off: Int, v: Long): Int {
        for (i in 0 until 8) b[off + i] = (v ushr (56 - 8 * i)).toByte()
        return off + 8
    }
}

/**
 * The parsed Ptm (finish-provisioning `Response.ptm`, base64 on the wire) — live-pinned from
 * the session-19f capture (`cap_ptm.bin`, 503 B): the finish reader's u32/[T;N]/const-bytes/
 * u32/Vec sequence (17f1f1e–17f2294) resolves to
 * `[u32 BE field1][seed 16][u32 BE payloadLen][payload payloadLen][trailing]` — live sample:
 * field1=4, seed=ptm[4:20], payloadLen=448, payload=ptm[24:472]. The [seed] is the
 * `decryptPTM` chain seed (finish 17f2557's rcx — confirmed live = ptm[4:20]) and [payload]
 * feeds [ClearAdiProvision.decryptPtm] with `count = payload.size / 16` (17f2548).
 */
data class Ptm(
    val field1: Int,
    val seed: ByteArray,
    val payload: ByteArray,
    val trailing: ByteArray,
) {
    companion object {
        /** u32 + seed + u32 (the live sample's field1 = 4; role of the leading u32 unpinned). */
        private const val HEADER = 24

        fun parse(bytes: ByteArray): Ptm {
            if (bytes.size < HEADER) throw SpimFormatException("ptm shorter than its 24-B header (${bytes.size} B)")
            val field1 = beU32At(bytes, 0)
            val seed = bytes.copyOfRange(4, 20)
            val payloadLength = beU32At(bytes, 20)
            if (24 + payloadLength > bytes.size) {
                throw SpimFormatException("ptm payload Vec needs $payloadLength B, ${bytes.size - 24} available")
            }
            val payload = bytes.copyOfRange(24, 24 + payloadLength)
            val trailing = bytes.copyOfRange(24 + payloadLength, bytes.size)
            return Ptm(field1, seed, payload, trailing)
        }

        private fun beU32At(b: ByteArray, off: Int): Int =
            ((b[off].toInt() and 0xff) shl 24) or ((b[off + 1].toInt() and 0xff) shl 16) or
                ((b[off + 2].toInt() and 0xff) shl 8) or (b[off + 3].toInt() and 0xff)
    }
}

/**
 * `finish()`'s ProvisionedData — live-pinned from the session-19f capture (`cap_provisioned.bin`,
 * 0x78 B at 17f2e5a): a Rust struct `{metadata: Vec<u8>, client_secret: [u8;32], mid: [u8;60],
 * flavor: u8}` — NOT the decrypt output itself:
 * - metadata = the decrypt output's Vec content (length = the u32 BE at out[0]; 400 B live)
 * - client_secret = the session's RNG draw 2 (ctx+0x2910; live byte-verified)
 * - mid = the session's RNG draw 3 (ctx+0x2930; live byte-verified)
 * - the struct's flavor byte (ctx+0x296c = 0x01 in the live Mac run) uses its own numbering —
 *   distinct from the ClearAdiOtp flavor convention, so it is carried raw here.
 * The finish gate (17f2cd7–17f2d0d, decrypt staging vs ctx+0x28f0) is the decrypt output's
 * **out[408:440] == draw1** echo — the earlier "out[0:32]" reading was wrong.
 */
data class ProvisionedData(
    val metadata: ByteArray,
    val clientSecret: ByteArray,
    val mid: ByteArray,
) {
    companion object {
        /** Gate echo position in the decrypt output (out[408:440] == RNG draw 1). */
        const val GATE_AT = 408

        /**
         * Assembles ProvisionedData from the [ClearAdiProvision.decryptPtm] output. [out] must
         * carry `u32 BE metaLen` at 0, the metadata at 4, and the draw-1 echo at [GATE_AT] —
         * a mismatch throws (the server's PTM did not echo our gate material).
         */
        fun fromDecrypt(out: ByteArray, draw1: ByteArray, draw2: ByteArray, draw3: ByteArray): ProvisionedData {
            require(out.size >= GATE_AT + 32 + 4) { "decryptPTM output too short: ${out.size} B" }
            val metaLen = beU32(out, 0)
            require(4 + metaLen <= out.size) { "decryptPTM metadata length $metaLen exceeds the output" }
            require(out.copyOfRange(GATE_AT, GATE_AT + 32).contentEquals(draw1)) {
                "PTM gate mismatch: the decrypted PTM does not echo the client gate material (17f2cd7)"
            }
            return ProvisionedData(out.copyOfRange(4, 4 + metaLen), draw2, draw3)
        }

        private fun beU32(b: ByteArray, off: Int): Int =
            ((b[off].toInt() and 0xff) shl 24) or ((b[off + 1].toInt() and 0xff) shl 16) or
                ((b[off + 2].toInt() and 0xff) shl 8) or (b[off + 3].toInt() and 0xff)
    }
}
