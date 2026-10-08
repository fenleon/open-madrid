package dev.fenn.imessage.registration

/**
 * Static .rodata tables of the SignState::sign NAC-mint path (librust_lib_bluebubbles), embedded
 * as base64 source in [NacSignTablesData] (no Apple-derived binary ships in the repo) and decoded
 * once at first use. Names follow the verified Python models (sig_hand.py/sig_tail.py/sig_init.py);
 * the vaddr in each member's doc cites the source location in the .so. Word tables are stored
 * little-endian (the x86 memory image). State-embedded constants (region6f98/sel6fd8/maskC68/
 * pTable) were runtime constants of the binary, verified input- and body-independent.
 */
internal object NacSignTables {
    private val bins: List<ByteArray> = listOf(
        java.util.Base64.getMimeDecoder().decode(NacSignTablesData.signChunks0.joinToString("")),
        java.util.Base64.getMimeDecoder().decode(NacSignTablesData.signChunks1.joinToString("")),
    )

    private fun bytesAt(img: Int, off: Int, n: Int): ByteArray =
        bins[img].copyOfRange(off, off + n)

    private fun u16sAt(img: Int, off: Int, n: Int): IntArray = IntArray(n) { i ->
        val p = off + 2 * i
        (bins[img][p].toInt() and 0xff) or ((bins[img][p + 1].toInt() and 0xff) shl 8)
    }

    private fun wordsAt(img: Int, off: Int, n: Int): IntArray = IntArray(n) { i ->
        val p = off + 4 * i
        (bins[img][p].toInt() and 0xff) or
            ((bins[img][p + 1].toInt() and 0xff) shl 8) or
            ((bins[img][p + 2].toInt() and 0xff) shl 16) or
            ((bins[img][p + 3].toInt() and 0xff) shl 24)
    }

    private fun longsAt(img: Int, off: Int, n: Int): LongArray = LongArray(n) { i ->
        var v = 0L
        for (b in 7 downTo 0) v = (v shl 8) or (bins[img][off + 8 * i + b].toLong() and 0xff)
        v
    }

    /** .rodata 0x1a10f0 — 544 B. */
    val tG: ByteArray by lazy { bytesAt(0, 0, 544) }
    /** .rodata 0x2251d8 — 72 B. */
    val sel: LongArray by lazy { longsAt(1, 0, 72 / 8) }
    /** .rodata 0x225220 — 256 B. */
    val tB: ByteArray by lazy { bytesAt(1, 72, 256) }
    /** .rodata 0x225320 — 256 B. */
    val tA: ByteArray by lazy { bytesAt(1, 328, 256) }
    /** .rodata 0x225420 — 256 B. */
    val tC: ByteArray by lazy { bytesAt(1, 584, 256) }
    /** .rodata 0x225a98 — 512 B. */
    val k1: ByteArray by lazy { bytesAt(1, 840, 512) }
    /** .rodata 0x225c98 — 512 B. */
    val k2: ByteArray by lazy { bytesAt(1, 1352, 512) }
    /** .rodata 0x225e98 — 512 B. */
    val k3: ByteArray by lazy { bytesAt(1, 1864, 512) }
    /** .rodata 0x226098 — 128 B. */
    val phbIdx: LongArray by lazy { longsAt(1, 2376, 128 / 8) }
    /** .rodata 0x226118 — 512 B. */
    val phbT: ByteArray by lazy { bytesAt(1, 2504, 512) }
    /** .rodata 0x226318 — 56 B. */
    val fin: LongArray by lazy { longsAt(1, 3016, 56 / 8) }
    /** .rodata 0x22635b — 512 B. */
    val pheT: ByteArray by lazy { bytesAt(1, 3072, 512) }
    /** .rodata 0x226560 — 128 B. */
    val pheIdx: LongArray by lazy { longsAt(1, 3584, 128 / 8) }
    /** .rodata 0x2265e0 — 4608 B. */
    val tbl9: ByteArray by lazy { bytesAt(1, 3712, 4608) }
    /** .rodata 0x2277e0 — 112 B. */
    val mtxSrc: LongArray by lazy { longsAt(1, 8320, 112 / 8) }
    /** .rodata 0x227850 — 112 B. */
    val mtxDst: LongArray by lazy { longsAt(1, 8432, 112 / 8) }
    /** .rodata 0x2278c0 — 18 B. */
    val e16: IntArray by lazy { u16sAt(1, 8544, 18 / 2) }
    /** .rodata 0x2278d2 — 18 B. */
    val skip: IntArray by lazy { u16sAt(1, 8562, 18 / 2) }
    /** .rodata 0x2278f8 — 128 B. */
    val t1Sel: LongArray by lazy { longsAt(1, 8580, 128 / 8) }
    /** .rodata 0x227978 — 128 B. */
    val t2Sel: LongArray by lazy { longsAt(1, 8708, 128 / 8) }
    /** .rodata 0x2279f8 — 40960 B. */
    val t2Big: ByteArray by lazy { bytesAt(1, 8836, 40960) }
    /** per-round u32 T-tables (sig_tail.UTAB), 9 rounds x 8 slots x 256. */
    val utab: Array<Array<IntArray>> by lazy {
        Array(9) { r12 -> Array(8) { slot ->
            wordsAt(1, utabOffs[r12 * 8 + slot], 256)
        } }
    }
    private val utabOffs = intArrayOf(
        82564, 106116, 55940, 79492, 103044, 52868, 76420, 99972, 115332, 65156, 88708, 112260, 62084, 85636, 109188, 59012, 74372, 97924, 121476, 71300, 94852, 118404, 68228, 91780, 107140, 56964, 80516, 104068, 53892, 77444, 100996, 50820, 66180, 89732, 113284, 63108, 86660, 110212, 60036, 83588, 98948, 122500, 72324, 95876, 119428, 69252, 92804, 116356, 57988, 81540, 105092, 54916, 78468, 102020, 51844, 75396, 90756, 114308, 64132, 87684, 111236, 61060, 84612, 108164, 49796, 73348, 96900, 120452, 70276, 93828, 117380, 67204,
    )
    /** .rodata 0x243a40 — 136 B. */
    val ts17: LongArray by lazy { longsAt(1, 123524, 136 / 8) }
    /** .rodata 0x243ac8 — 136 B. */
    val md17: LongArray by lazy { longsAt(1, 123660, 136 / 8) }
    /** .rodata 0x243b50 — 256 B. */
    val t243b50: ByteArray by lazy { bytesAt(1, 123796, 256) }
    /** .rodata 0x243c50 — 256 B. */
    val t243c50: ByteArray by lazy { bytesAt(1, 124052, 256) }
    /** .rodata 0x243d50 — 256 B. */
    val t243d50: ByteArray by lazy { bytesAt(1, 124308, 256) }
    /** embedded constant — 16 B. */
    val region6f98: ByteArray by lazy { bytesAt(1, 124564, 16) }
    /** embedded constant — 16 B. */
    val sel6fd8: ByteArray by lazy { bytesAt(1, 124580, 16) }
    /** embedded constant — 8 B. */
    val maskC68: ByteArray by lazy { bytesAt(1, 124596, 8) }
    /** embedded constant — 1792 B. */
    val pTable: ByteArray by lazy { bytesAt(1, 124604, 1792) }
}
