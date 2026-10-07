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
 * 0x20 size setup is at 17ef00b — and two u32 reads 17ef05f/17ef3e8). Empirically pinned
 * against the live library: a Spim whose bytes after the payload are ≤ 23 parses fine and
 * ≥ 24 fails with error 0x41 regardless of the payload length (60…256 tested). Their exact
 * semantics are TODO(live-capture).
 */
data class Spim(
    val field1: Int,
    val payloadLength: Int,
    val payload: ByteArray,
) {
    companion object {
        /** Minimum reader requirement (`cmp rdx,0x3; ja` 17eec6c): the first u32 must fit. */
        private const val MIN_LEN = 4
        /** `cmp QWORD PTR […],0x3b; ja` 17efb33 — the payload Vec must exceed 59 bytes. */
        private const val MIN_PAYLOAD = 60
        /** Live-pinned leftover tolerance: > 23 trailing bytes ⇒ error 0x41. TODO(live-capture). */
        private const val MAX_LEFTOVER = 23

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
            val leftover = bytes.size - 8 - payloadLength
            if (leftover > MAX_LEFTOVER) {
                throw SpimFormatException("spim has $leftover trailing bytes; the live binary tolerates ≤ 23 (error 0x41)")
            }
            return Spim(field1, payloadLength, payload)
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
 * The two trailing 256-bit Cpim fields (provisioning.md §6 items 8–9, written as deku
 * `write_bits(0x100)` calls at 17effc9/17f0338/17f0444). The asm shows the material they are
 * derived from — `spim_map_signature` over a zeroed 16-byte block (17f0914–17f0931) and a
 * SHA-256 over the `encrypt(session, iv16, payload)` output, where the IV is assembled from
 * the parsed Spim's trailing fields (17f0848–17f0888) — but their exact wire assembly is not
 * provable from the dump alone: TODO(live-capture). The production seal is wired after that
 * capture; tests seal deterministically.
 */
fun interface CpimTailSeal {
    /**
     * Returns the pair of 32-byte Cpim tail fields. [sessionKey] is the 16-byte session key,
     * [encryptedPayload] the `encrypt(session, iv, payload)` output, [signatureOfZeroBlock]
     * the `spimMapSignature(ByteArray(16))` output, [sha256OfEncrypted] the SHA-256 digest of
     * [encryptedPayload] — everything the asm shows feeding the region.
     */
    fun seal(
        sessionKey: ByteArray,
        encryptedPayload: ByteArray,
        signatureOfZeroBlock: ByteArray,
        sha256OfEncrypted: ByteArray,
    ): Pair<ByteArray, ByteArray>
}

/**
 * The Cpim wire bytes (`new()`'s deku Writer output, provisioning.md §6 items 1–9):
 *
 * 1. `00 00 00 20` u32 BE (17efe9b) — the Vec length prefix of item 2
 * 2. `encsec(draw2)` (Vec#1, 32 B — encsec call 17efd5e on the second RNG draw)
 * 3. `00 00 00 20` u32 BE — length prefix of item 4
 * 4. `draw1` raw (Vec#2, 32 B — the first RNG draw copied untouched, 17efc95)
 * 5. the 60-byte blob: the caller's ≤ 60-byte `extra` slice, padded with the third RNG draw
 *    (the extra memcpy 17efb21 lands on the draw-3 slot, then the struct copy 17efcb5 takes
 *    exactly 60 bytes into the Cpim struct)
 * 6. [gsaArg] as u64 BE — the omnisette reference passes −2 ("GSA"): `FF FF FF FF FF FF FF FE`
 * 7. u32 BE — `bswap` of the little-endian dword at draw3[8..12] (17efc3c → struct +0x7c)
 * 8–9. the two 256-bit [CpimTailSeal] fields — TODO(live-capture)
 */
object Cpim {

    /** `extra` must fit the fixed 60-byte blob slot (`cmp rdx,0x3d; jae` → error, 17efb17). */
    const val MAX_EXTRA = 60
    private const val BLOB_LEN = 60

    fun build(
        rng: ClearAdiRng,
        extra: ByteArray,
        gsaArg: Long,
        sessionCtx: ByteArray,
        payload240: ByteArray,
        tail: CpimTailSeal?,
    ): ByteArray {
        require(extra.size <= MAX_EXTRA) { "extra blob of ${extra.size} B exceeds the 60 B Cpim slot (17efb17)" }
        val draw1 = rng.draw(32)
        val draw2 = rng.draw(32)
        val draw3 = rng.draw(60)
        val vec1 = ClearAdiProvision.encsec(draw2)
        val blob = extra + draw3.copyOfRange(extra.size, BLOB_LEN)
        val item7 = leU32(draw3, 8)

        val out = ByteArray(4 + 32 + 4 + 32 + BLOB_LEN + 8 + 4 + 32 + 32)
        var p = 0
        p = putBeU32(out, p, 32)
        System.arraycopy(vec1, 0, out, p, vec1.size); p += vec1.size
        p = putBeU32(out, p, 32)
        System.arraycopy(draw1, 0, out, p, draw1.size); p += draw1.size
        System.arraycopy(blob, 0, out, p, blob.size); p += blob.size
        p = putBeU64(out, p, gsaArg)
        p = putBeU32(out, p, item7)
        if (tail == null) {
            throw IllegalStateException(
                "Cpim tail fields (§6 items 8–9) need the live capture — no CpimTailSeal supplied (TODO(live-capture))",
            )
        }
        val iv16 = ByteArray(16) // IV assembled from the Spim's trailing fields — TODO(live-capture)
        val encrypted = ClearAdiProvision.encrypt(sessionCtx, iv16, payload240)
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(encrypted)
        val signature = ClearAdiProvision.spimMapSignature(ByteArray(16))
        val (field8, field9) = tail.seal(
            ClearAdiProvision.sessionKey(sessionCtx),
            encrypted,
            signature,
            digest,
        )
        require(field8.size == 32 && field9.size == 32) { "Cpim tail fields must be 32 B each" }
        System.arraycopy(field8, 0, out, p, 32); p += 32
        System.arraycopy(field9, 0, out, p, 32); p += 32
        return out.copyOf(p)
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

    private fun leU32(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xff) or ((b[off + 1].toInt() and 0xff) shl 8) or
            ((b[off + 2].toInt() and 0xff) shl 16) or ((b[off + 3].toInt() and 0xff) shl 24)
}

/**
 * The parsed Ptm (finish-provisioning `Response.ptm`, base64 on the wire). Same reader family
 * as [Spim] (finish.asm 17f1f1e–17f2294): `field1` u32 BE first, then a lenient Vec (every
 * candidate shape accepted by the live binary, error 0) whose bytes feed
 * [ClearAdiProvision.decryptPtm] with `count = payload.size / 16` (17f2548).
 * The live binary accepts every candidate shape thrown at it (u32 alone through 128 B tails,
 * all error 0) — the trailing [T;N]/read_bytes_const/u32 reads (17f1f6a/17f1fd4/17f20e5) are
 * lenient; their exact semantics TODO(live-capture).
 */
data class Ptm(
    val field1: Int,
    val payload: ByteArray,
) {
    companion object {
        /** Minimum reader requirement (finish `cmp …,0x3; ja` 17f1eec → 17f1f1e). */
        private const val MIN_LEN = 4

        fun parse(bytes: ByteArray): Ptm {
            if (bytes.size < MIN_LEN) throw SpimFormatException("ptm shorter than the first u32 (${bytes.size} B)")
            val field1 = ((bytes[0].toInt() and 0xff) shl 24) or ((bytes[1].toInt() and 0xff) shl 16) or
                ((bytes[2].toInt() and 0xff) shl 8) or (bytes[3].toInt() and 0xff)
            // Lenient Vec: takes the whole tail after the first u32 — the live binary accepts
            // every candidate shape (u32 alone through 128 B tails, all error 0), so field1
            // is not enforced as a length (its role is TODO(live-capture)).
            return Ptm(field1, bytes.copyOfRange(4, bytes.size))
        }
    }
}

/**
 * `finish()`'s return — the raw 0x78-byte ProvisionedData struct (17f2dec–17f2e56):
 * +0x00 16 B, +0x10 u64, +0x18 u64, +0x20 16 B, +0x30..0x70 64 B (metadata blob), +0x70 u32,
 * +0x74 u8 (flavor). Which bytes are `mid` vs `client_secret` is NOT provable from the dump
 * (an OpenBubbles provisioning run under gdb is pending) — the cross-check against the
 * OTP-path report's ProvisionedMachine (client_info 400/208 B, mid 32 B, secret 60 B,
 * flavor) is likewise unconfirmed: TODO(live-capture) on the field mapping. Named accessors
 * only; nothing is invented.
 */
data class ProvisionedData(val raw: ByteArray) {
    init {
        require(raw.size >= 0x78) { "ProvisionedData must be 0x78 bytes, got ${raw.size}" }
    }

    /** +0x00, 16 B (role unproven). */
    val block00: ByteArray get() = raw.copyOfRange(0x00, 0x10)
    /** +0x10, u64 LE (role unproven). */
    val word10: Long get() = le64(raw, 0x10)
    /** +0x18, u64 LE (role unproven). */
    val word18: Long get() = le64(raw, 0x18)
    /** +0x20, 16 B (role unproven). */
    val block20: ByteArray get() = raw.copyOfRange(0x20, 0x30)
    /** +0x30..0x70, 64 B — the metadata blob per the OTP-path report's layout cross-check. */
    val metadata64: ByteArray get() = raw.copyOfRange(0x30, 0x70)
    /** +0x70, u32 LE. */
    val word70: Int get() = le32(raw, 0x70)
    /** +0x74, u8 — the flavor byte (Mac = 0, IOS = 1, per the ClearAdiOtp flavor convention). */
    val flavor: Int get() = raw[0x74].toInt() and 0xff

    private fun le32(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xff) or ((b[off + 1].toInt() and 0xff) shl 8) or
            ((b[off + 2].toInt() and 0xff) shl 16) or ((b[off + 3].toInt() and 0xff) shl 24)

    private fun le64(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 7 downTo 0) v = (v shl 8) or (b[off + i].toLong() and 0xff)
        return v
    }
}
