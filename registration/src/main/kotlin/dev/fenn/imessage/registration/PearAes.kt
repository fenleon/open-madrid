package dev.fenn.imessage.registration

/**
 * Kotlin transcription of the pear_aes layer of the NAC white-box (OpenBubbles absinthe,
 * librust_lib_bluebubbles). An AES-128-shaped cipher with pluggable S-box/rcon, a per-register
 * state-slot layout, 9 T-table rounds (not 10), and permuted final byte maps — the quirks are
 * load-bearing and reproduced exactly. Address citations refer to that .so; every model here is
 * verified byte-exact against live runs (registration/dev/clearadi/captures/nac-oracle/NAC-NOTES.md,
 * pear.py + dec_model.py, from which all constant maps below were extracted mechanically).
 */
internal object PearAes {

    // ---- key schedules -------------------------------------------------------

    /**
     * create_rounds (0x17b8e80): standard AES-128 expansion (RotWord/SubWord over the given
     * sbox, table-indexed rcon, w[i-4] xor) producing 44 little-endian words.
     */
    internal fun createRounds(key16: ByteArray, sbox: ByteArray, rcon: ByteArray): IntArray {
        val w = IntArray(44)
        for (i in 0 until 4) {
            w[i] = (key16[4 * i].toInt() and 0xff) or
                ((key16[4 * i + 1].toInt() and 0xff) shl 8) or
                ((key16[4 * i + 2].toInt() and 0xff) shl 16) or
                ((key16[4 * i + 3].toInt() and 0xff) shl 24)
        }
        var ridx = 1
        for (i in 4 until 44) {
            var t = w[i - 1]
            if (i % 4 == 0) {
                t = (t ushr 8) or (t shl 24)
                t = (sbox[t and 0xff].toInt() and 0xff) or
                    ((sbox[(t ushr 8) and 0xff].toInt() and 0xff) shl 8) or
                    ((sbox[(t ushr 16) and 0xff].toInt() and 0xff) shl 16) or
                    ((sbox[(t ushr 24) and 0xff].toInt() and 0xff) shl 24)
                t = t xor (rcon[ridx].toInt() and 0xff)
                ridx++
            }
            w[i] = w[i - 4] xor t
        }
        return w
    }

    private fun packWords(w: IntArray): ByteArray {
        val out = ByteArray(4 * w.size)
        for (i in w.indices) {
            out[4 * i] = w[i].toByte()
            out[4 * i + 1] = (w[i] ushr 8).toByte()
            out[4 * i + 2] = (w[i] ushr 16).toByte()
            out[4 * i + 3] = (w[i] ushr 24).toByte()
        }
        return out
    }

    /**
     * init_key (0x17b9360): every key byte through the S1 scramble, then the schedule with
     * S2/R2. Returns the 176-byte PAESKey (11 round keys, words little-endian).
     */
    internal fun initKey(key16: ByteArray): ByteArray {
        require(key16.size == 16) { "init_key: key must be 16 bytes" }
        val scrambled = ByteArray(16) { PearTables.s1[key16[it].toInt() and 0xff] }
        return packWords(createRounds(scrambled, PearTables.s2, PearTables.r2))
    }

    /**
     * establish_key (0x17b9220): schedule with S3/R3 from the raw 16-byte key, then an
     * in-place T-transform of round-key blocks 1..9 (blocks 0 and 10 untouched): each word is
     * the XOR of four est-transform lookups over the block's own bytes, in the fitted table
     * order et0[b3] ^ et3[b2] ^ et1[b0] ^ et2[b1] (verified vs the 01_estkey captures).
     */
    internal fun establishKey(key16: ByteArray): ByteArray {
        require(key16.size == 16) { "establish_key: key must be 16 bytes" }
        val w = createRounds(key16, PearTables.s3, PearTables.r3)
        val t0 = PearTables.et0
        val t1 = PearTables.et1
        val t2 = PearTables.et2
        val t3 = PearTables.et3
        for (k in 1..9) {
            for (j in 0 until 4) {
                val idx = 4 * k + j
                val word = w[idx]
                val b0 = word and 0xff
                val b1 = (word ushr 8) and 0xff
                val b2 = (word ushr 16) and 0xff
                val b3 = (word ushr 24) and 0xff
                w[idx] = t0[b3] xor t3[b2] xor t1[b0] xor t2[b1]
            }
        }
        return packWords(w)
    }

    // ---- encrypt_cbc (0x17b86c0) ----------------------------------------------

    /**
     * State is 16 bytes in the asm register-slot order: [0..3] = rax b0..b3, then rbx, rcx,
     * rdx, r8, r9, r10, r11, rdi, s8, s34, s38, s3c. Whitening feeds pt ^ chain ^ rk0 into
     * the slots through this index map (st[i] = x[WHITEN[i]]; NAC-NOTES step 1).
     */
    private val WHITEN = intArrayOf(12, 13, 14, 15, 10, 9, 11, 7, 3, 2, 5, 6, 0, 1, 8, 4)

    /** Round table inputs: Σw = ta[s0] ^ tb[s1] ^ tc[s2] ^ td[s3] over these slots (step 2). */
    private val ROUND_IN = intArrayOf(12, 3, 10, 4, 15, 8, 5, 2, 14, 7, 1, 9, 0, 6, 13, 11)

    /** Round update: st'[i] = beByte(ob[OUT_W[i]], OUT_B[i]) ^ rk[OUT_K[i]] (step 2 slot map). */
    private val ROUND_OUT_W = intArrayOf(3, 3, 3, 3, 2, 2, 2, 1, 0, 0, 1, 1, 0, 0, 2, 1)
    private val ROUND_OUT_B = intArrayOf(0, 1, 2, 3, 2, 1, 3, 3, 3, 2, 1, 2, 0, 1, 0, 0)
    private val ROUND_OUT_K = intArrayOf(12, 13, 14, 15, 10, 9, 11, 7, 3, 2, 5, 6, 0, 1, 8, 4)

    /** Final-round permutation (step 3): ct[i] = SE[st9[FINAL_P[i]]] ^ rk11[i]. */
    private val FINAL_P = intArrayOf(12, 10, 4, 3, 15, 5, 2, 8, 14, 1, 9, 7, 0, 13, 11, 6)

    /**
     * encrypt_cbc: per block, chain = iv then the previous ciphertext. 9 rounds over round-key
     * blocks 1..9; the Σ words are emitted as big-endian bytes (the asm bswaps) before the
     * fused round-key xor; the final round applies SE over the permuted state.
     */
    internal fun encryptCbc(data: ByteArray, iv: ByteArray, rk176: ByteArray): ByteArray {
        require(rk176.size == 176) { "encrypt_cbc: need 176 bytes of round keys" }
        require(data.size % 16 == 0) { "encrypt_cbc: data length must be a multiple of 16" }
        val ta = PearTables.ta
        val tb = PearTables.tb
        val tc = PearTables.tc
        val td = PearTables.td
        val se = PearTables.se
        val out = ByteArray(data.size)
        var chain = iv.copyOf()
        for (off in 0 until data.size step 16) {
            // whitening
            val st = ByteArray(16)
            for (i in 0 until 16) {
                st[i] = (data[off + WHITEN[i]].toInt() xor
                    chain[WHITEN[i]].toInt() xor rk176[WHITEN[i]].toInt()).toByte()
            }
            for (r in 1 until 10) {
                val rkb = 16 * r
                val ob = IntArray(4)
                for (word in 0 until 4) {
                    val sel = 4 * word
                    ob[word] = ta[st[ROUND_IN[sel]].toInt() and 0xff] xor
                        tb[st[ROUND_IN[sel + 1]].toInt() and 0xff] xor
                        tc[st[ROUND_IN[sel + 2]].toInt() and 0xff] xor
                        td[st[ROUND_IN[sel + 3]].toInt() and 0xff]
                }
                val next = ByteArray(16)
                for (i in 0 until 16) {
                    val obByte = (ob[ROUND_OUT_W[i]] ushr (24 - 8 * ROUND_OUT_B[i])) and 0xff
                    next[i] = (obByte xor (rk176[rkb + ROUND_OUT_K[i]].toInt() and 0xff)).toByte()
                }
                for (i in 0 until 16) st[i] = next[i]
            }
            for (i in 0 until 16) {
                out[off + i] = (se[st[FINAL_P[i]].toInt() and 0xff].toInt() xor
                    (rk176[160 + i].toInt() and 0xff)).toByte()
            }
            chain = out.copyOfRange(off, off + 16)
        }
        return out
    }

    // ---- decrypt_cbc (0x17b80c0) ----------------------------------------------

    /**
     * decrypt_cbc: 9 table rounds backward over the round-key blocks rk[160]..rk[32], with the
     * round key fused into the table index (x[i] = s[i] ^ rkBlock[i]); the dec T-tables combine
     * in the rows below, parsed from dec_model.py (tables dt0..dt3 = 0x2448b8/0x244cb8/
     * 0x2450b8/0x2454b8). Final: pt[i] = SDI[st9 ^ rk1][P[i]] ^ chain[i] ^ rk0[i] with P =
     * [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3] — a different permutation from the encrypt-side map.
     */
    private val DECRYPT_P = intArrayOf(0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3)

    /** Per output word: (table, state-byte) pairs, table index into (dt0, dt1, dt2, dt3). */
    private val DEC_ROUND = intArrayOf(
        1, 0, 0, 7, 2, 13, 3, 10,
        1, 4, 0, 11, 2, 1, 3, 14,
        1, 8, 0, 15, 2, 5, 3, 2,
        1, 12, 0, 3, 2, 9, 3, 6,
    )

    internal fun decryptCbc(ct: ByteArray, iv: ByteArray, rk176: ByteArray): ByteArray {
        require(rk176.size == 176) { "decrypt_cbc: need 176 bytes of round keys" }
        require(ct.size % 16 == 0) { "decrypt_cbc: ct length must be a multiple of 16" }
        val dt = arrayOf(PearTables.dt0, PearTables.dt1, PearTables.dt2, PearTables.dt3)
        val sdi = PearTables.sdi
        val out = ByteArray(ct.size)
        var chain = iv.copyOf()
        for (off in 0 until ct.size step 16) {
            val s = ByteArray(16) { ct[off + it] }
            var b = 160
            while (b >= 32) { // round-key blocks 10..2
                val x = IntArray(16) { (s[it].toInt() and 0xff) xor (rk176[b + it].toInt() and 0xff) }
                val w = IntArray(4)
                for (j in 0 until 4) {
                    var acc = 0
                    for (t in 0 until 4) {
                        val tab = DEC_ROUND[8 * j + 2 * t]
                        val sel = DEC_ROUND[8 * j + 2 * t + 1]
                        acc = acc xor dt[tab][x[sel]]
                    }
                    w[j] = acc
                }
                for (j in 0 until 4) {
                    s[4 * j] = w[j].toByte()
                    s[4 * j + 1] = (w[j] ushr 8).toByte()
                    s[4 * j + 2] = (w[j] ushr 16).toByte()
                    s[4 * j + 3] = (w[j] ushr 24).toByte()
                }
                b -= 16
            }
            val st9 = IntArray(16) { (s[it].toInt() and 0xff) xor (rk176[16 + it].toInt() and 0xff) }
            for (i in 0 until 16) {
                val v = sdi[st9[DECRYPT_P[i]]]
                out[off + i] = (v.toInt() xor chain[i].toInt() xor rk176[i].toInt()).toByte()
            }
            chain = ct.copyOfRange(off, off + 16)
        }
        return out
    }
}
