package dev.fenn.imessage.registration

/**
 * Static .rodata tables of the pear_aes / NAC white-box (librust_lib_bluebubbles), embedded as
 * base64 source in [PearTablesData] (no Apple-derived binary ships in the repo) and decoded once
 * at first use. Names follow the verified Python models; the vaddr in each member's doc cites the
 * source location in the .so. Word tables are stored little-endian (the x86 memory image).
 */
internal object PearTables {
    private val bin: ByteArray by lazy {
        java.util.Base64.getMimeDecoder().decode(PearTablesData.pearChunks.joinToString(""))
    }

    private fun bytesAt(off: Int, n: Int): ByteArray = bin.copyOfRange(off, off + n)

    private fun wordsAt(off: Int, n: Int): IntArray = IntArray(n) { i ->
        val p = off + 4 * i
        (bin[p].toInt() and 0xff) or
            ((bin[p + 1].toInt() and 0xff) shl 8) or
            ((bin[p + 2].toInt() and 0xff) shl 16) or
            ((bin[p + 3].toInt() and 0xff) shl 24)
    }

    /** .rodata 0x1a0ea0 — domergestep2 constant appended to the 64-B block. */
    val iv2: ByteArray by lazy { bytesAt(0, 16) }
    /** .rodata 0x2246f6 — key_establishment post-decrypt byte map. */
    val sdat: ByteArray by lazy { bytesAt(16, 256) }
    /** .rodata 0x2247f6 — key_establishment pre-decrypt byte map (iv + body). */
    val skey: ByteArray by lazy { bytesAt(272, 256) }
    /** .rodata 0x224c22 — domergestep2 final substitution (TC). */
    val dmc: ByteArray by lazy { bytesAt(528, 256) }
    /** .rodata 0x224d22 — domergestep2 sbox A (TA). */
    val dma: ByteArray by lazy { bytesAt(784, 256) }
    /** .rodata 0x224e22 — domergestep2 sbox B (TB). */
    val dmb: ByteArray by lazy { bytesAt(1040, 256) }
    /** .rodata 0x224f22 — domergestep2 key-schedule permutation (KP). */
    val kp: ByteArray by lazy { bytesAt(1296, 256) }
    /** .rodata 0x243f60 — init_key input scramble. */
    val s1: ByteArray by lazy { bytesAt(1552, 256) }
    /** .rodata 0x2447b5 — decrypt final inv-sbox (SDI; note the +5 offset vs the b8-aligned dec T-tables). */
    val sdi: ByteArray by lazy { bytesAt(1808, 256) }
    /** .rodata 0x2448b8 — decrypt T-table 0. */
    val dt0: IntArray by lazy { wordsAt(2064, 256) }
    /** .rodata 0x244cb8 — decrypt T-table 1. */
    val dt1: IntArray by lazy { wordsAt(3088, 256) }
    /** .rodata 0x2450b8 — decrypt T-table 2. */
    val dt2: IntArray by lazy { wordsAt(4112, 256) }
    /** .rodata 0x2454b8 — decrypt T-table 3. */
    val dt3: IntArray by lazy { wordsAt(5136, 256) }
    /** .rodata 0x2458b8 — encrypt final-round sbox. */
    val se: ByteArray by lazy { bytesAt(6160, 256) }
    /** .rodata 0x2459b8 — encrypt T-table B. */
    val tb: IntArray by lazy { wordsAt(6416, 256) }
    /** .rodata 0x245db8 — encrypt T-table A. */
    val ta: IntArray by lazy { wordsAt(7440, 256) }
    /** .rodata 0x2461b8 — encrypt T-table C. */
    val tc: IntArray by lazy { wordsAt(8464, 256) }
    /** .rodata 0x2465b8 — encrypt T-table D. */
    val td: IntArray by lazy { wordsAt(9488, 256) }
    /** .rodata 0x2469b8 — establish_key schedule sbox. */
    val s3: ByteArray by lazy { bytesAt(10512, 256) }
    /** .rodata 0x246ab8 — establish_key schedule rcon (only bytes 1..10 consumed; the tail overlaps the est-transform tables). */
    val r3: ByteArray by lazy { bytesAt(10768, 256) }
    /** .rodata 0x246ac4 — establish_key transform T-table 0. */
    val et0: IntArray by lazy { wordsAt(11024, 256) }
    /** .rodata 0x246ec4 — establish_key transform T-table 1. */
    val et1: IntArray by lazy { wordsAt(12048, 256) }
    /** .rodata 0x2472c4 — establish_key transform T-table 2. */
    val et2: IntArray by lazy { wordsAt(13072, 256) }
    /** .rodata 0x2476c4 — establish_key transform T-table 3. */
    val et3: IntArray by lazy { wordsAt(14096, 256) }
    /** .rodata 0x247ac4 — init_key schedule sbox. */
    val s2: ByteArray by lazy { bytesAt(15120, 256) }
    /** .rodata 0x247bc4 — init_key schedule rcon (only bytes 1..10 consumed). */
    val r2: ByteArray by lazy { bytesAt(15376, 256) }
}
