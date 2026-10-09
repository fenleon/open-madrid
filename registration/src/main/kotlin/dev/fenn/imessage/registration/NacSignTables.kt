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
    /** .rodata 0x2256b8 — 992 B. */
    val tsel6f98: ByteArray by lazy { bytesAt(1, 840, 992) }
    /** .rodata 0x225a98 — 512 B. */
    val k1: ByteArray by lazy { bytesAt(1, 1832, 512) }
    /** .rodata 0x225c98 — 512 B. */
    val k2: ByteArray by lazy { bytesAt(1, 2344, 512) }
    /** .rodata 0x225e98 — 512 B. */
    val k3: ByteArray by lazy { bytesAt(1, 2856, 512) }
    /** .rodata 0x226098 — 128 B. */
    val phbIdx: LongArray by lazy { longsAt(1, 3368, 128 / 8) }
    /** .rodata 0x226118 — 512 B. */
    val phbT: ByteArray by lazy { bytesAt(1, 3496, 512) }
    /** .rodata 0x226318 — 56 B. */
    val fin: LongArray by lazy { longsAt(1, 4008, 56 / 8) }
    /** .rodata 0x22635b — 512 B. */
    val pheT: ByteArray by lazy { bytesAt(1, 4064, 512) }
    /** .rodata 0x226560 — 128 B. */
    val pheIdx: LongArray by lazy { longsAt(1, 4576, 128 / 8) }
    /** .rodata 0x2265e0 — 4608 B. */
    val tbl9: ByteArray by lazy { bytesAt(1, 4704, 4608) }
    /** .rodata 0x2277e0 — 112 B. */
    val mtxSrc: LongArray by lazy { longsAt(1, 9312, 112 / 8) }
    /** .rodata 0x227850 — 112 B. */
    val mtxDst: LongArray by lazy { longsAt(1, 9424, 112 / 8) }
    /** .rodata 0x2278c0 — 18 B. */
    val e16: IntArray by lazy { u16sAt(1, 9536, 18 / 2) }
    /** .rodata 0x2278d2 — 18 B. */
    val skip: IntArray by lazy { u16sAt(1, 9554, 18 / 2) }
    /** .rodata 0x2278f8 — 128 B. */
    val t1Sel: LongArray by lazy { longsAt(1, 9572, 128 / 8) }
    /** .rodata 0x227978 — 128 B. */
    val t2Sel: LongArray by lazy { longsAt(1, 9700, 128 / 8) }
    /** .rodata 0x2279f8 — 40960 B. */
    val t2Big: ByteArray by lazy { bytesAt(1, 9828, 40960) }
    /** per-round u32 T-tables (sig_tail.UTAB), 9 rounds x 8 slots x 256. */
    val utab: Array<Array<IntArray>> by lazy {
        Array(9) { r12 -> Array(8) { slot ->
            wordsAt(1, utabOffs[r12 * 8 + slot], 256)
        } }
    }
    private val utabOffs = intArrayOf(
        83556, 107108, 56932, 80484, 104036, 53860, 77412, 100964, 116324, 66148, 89700, 113252, 63076, 86628, 110180, 60004, 75364, 98916, 122468, 72292, 95844, 119396, 69220, 92772, 108132, 57956, 81508, 105060, 54884, 78436, 101988, 51812, 67172, 90724, 114276, 64100, 87652, 111204, 61028, 84580, 99940, 123492, 73316, 96868, 120420, 70244, 93796, 117348, 58980, 82532, 106084, 55908, 79460, 103012, 52836, 76388, 91748, 115300, 65124, 88676, 112228, 62052, 85604, 109156, 50788, 74340, 97892, 121444, 71268, 94820, 118372, 68196,
    )
    /** .rodata 0x243a40 — 136 B. */
    val ts17: LongArray by lazy { longsAt(1, 124516, 136 / 8) }
    /** .rodata 0x243ac8 — 136 B. */
    val md17: LongArray by lazy { longsAt(1, 124652, 136 / 8) }
    /** .rodata 0x243b50 — 256 B. */
    val t243b50: ByteArray by lazy { bytesAt(1, 124788, 256) }
    /** .rodata 0x243c50 — 256 B. */
    val t243c50: ByteArray by lazy { bytesAt(1, 125044, 256) }
    /** .rodata 0x243d50 — 256 B. */
    val t243d50: ByteArray by lazy { bytesAt(1, 125300, 256) }
}
