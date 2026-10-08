package dev.fenn.imessage.registration

/**
 * Kotlin transcription of SignState::sign (0x179de50, open_absinthe::nac NAC mint "C5" — the
 * 16-byte signature over the 480-byte validation body), from the byte-exact pure-Python models
 * sig_hand.py / sig_init.py / sig_tail.py (NAC-NOTES.md; STAGE7-10-REPORT.md session 6:
 * e2e verified against the live stamp, 270/270 base + 225/225 mod tail rounds, `sig_hand.py
 * verify` 20/20). Tables come from [NacSignTables]; state-embedded constants (region 0x6f98,
 * 0x6fd8 selectors, 0x6fe8 mask/C68, P table) were runtime constants of the binary, verified
 * input- and body-independent.
 *
 * Pipeline: static state build (stages 1–9: scatter, u32 flag table, perms, divisor, key map,
 * keygen, matrix copy + phases B–E, 16 position rounds) with the input mapped in (rand16 at
 * state+0x15f0, blob480 at state+0x1600), then the 30-run tail — per run: RS32/rec0/r70ab init,
 * run-start feedback, soup57/soup80, 9 threshold-cipher rounds (r70ab ^= soup after rounds 3/7),
 * staging from the generator soup, final formula, and the chain1 fold with tmp. sig16 = the 30th
 * final-formula output.
 *
 * The N constant (scatter size 2571 and the RS-init index modulo) is the model's pinned value —
 * byte-faithful to the verified Python.
 */
internal object NacSign {

    /** SignState::sign -> the 16-byte sig16. blob480 must be exactly 480 bytes. */
    internal fun sign(body576: ByteArray, rand16: ByteArray, blob480: ByteArray): ByteArray {
        require(blob480.size == 480) { "sign: blob480 must be exactly 480 bytes, got ${blob480.size}" }
        val bs = buildState(body576, rand16, blob480)
        val state = bs.state
        var chain1 = IntArray(16) { i ->
            foldStep(rand16[i].toInt() and 0xff, blob480[i].toInt() and 0xff)
        }
        var tmp = ByteArray(16)
        for (run in 0 until 30) {
            val (rs, r0, r70ab) = rsInit(state, bs.bufs, chain1)
            val region = NacSignTables.region6f98
            val ts = TailState(rs, r0, r70ab, intArrayOf(
                region[4].toInt() and 0xff, region[5].toInt() and 0xff,
                region[7].toInt() and 0xff, region[10].toInt() and 0xff))
            runstartFeedback(ts, rs[16], rs[12])
            // [rsp+0x80] is re-seeded per run with chain1[10] — no cross-run chaining
            val s = soup(state, chain1, chain1[10], chain1[7], chain1[4])
            var sp20 = 0
            for (r12 in 0..8) {
                val sp = cipherRound(ts, state, r12)
                if (r12 == 3) ts.r70ab = s.first xor 0x9b
                else if (r12 == 7) ts.r70ab = s.second xor 0x9b
                if (r12 == 8) sp20 = sp
            }
            for (i in rs.indices) state[0x6ff0 + i] = rs[i].toByte()
            for (i in ts.rec.indices) state[0x7001 + i] = ts.rec[i].toByte()
            state[0x70ab] = ts.r70ab.toByte()
            val stg = stagingFromSoup(state, bs.vecB, bs.n, sp20)
            tmp = finalFormula(stg, state)
            if (run < 29) {
                chain1 = IntArray(16) { i ->
                    foldStep(tmp[i].toInt() and 0xff, blob480[16 * (run + 1) + i].toInt() and 0xff)
                }
            }
        }
        return tmp
    }

    // ---------------------------------------------------------------- state --

    private class BuiltState(
        val state: ByteArray,
        val bufs: Array<ByteArray>,
        val vecB: ByteArray,
        val n: Int,
    )

    /** Static state (0x7888 B) + derived pieces for one sign() call (sig_init.build_state). */
    private fun buildState(body: ByteArray, rand16: ByteArray, blob480: ByteArray): BuiltState {
        val t = NacSignTables
        val state = ByteArray(0x7888)
        val u32t = u32tab()
        val (perm1, perm2) = perms(u32t)
        for (i in 0..255) putU32le(state, 0x21d8 + 4 * i, perm2[i])
        for (i in 0..255) putU32le(state, 0x1dd8 + 4 * i, perm1[i])
        putU64le(state, 0x17e0, N.toLong())
        val kbmap = mapKey(divisor(body))
        kbmap.copyInto(state, 0x1be8)
        val kg = keygen(body, kbmap)
        kg.copyInto(state, 0x2678)
        phaseBCDE(body, kbmap, u32t, state)
        val (n, _, vecA, vecB) = vecABMut(body, u32t)
        rounds(state)
        t.region6f98.copyInto(state, 0x6f98)
        t.sel6fd8.copyInto(state, 0x6fd8)
        t.maskC68.copyInto(state, 0x6fe8)
        t.pTable.copyInto(state, 0x6898)
        rand16.copyInto(state, 0x15f0)
        blob480.copyInto(state, 0x1600)
        val bufs = genBufs(state.copyOfRange(0x2678, 0x2678 + 544), vecA)
        return BuiltState(state, bufs, vecB, n)
    }

    // ------------------------------------------------- stage 1: scatter ------

    private fun scatter(body: ByteArray): Pair<Int, ByteArray> {
        val n = (((body[202].toInt() xor body[250].toInt()) and 0xff) shl 8) or
            ((body[195].toInt() xor body[243].toInt()) and 0xff)
        val buf = ByteArray(n)
        for (i in 0 until n) {
            buf[i] = body[(3 * (body[i % 576].toInt() and 0xff) + i + 2) % 576]
        }
        return n to buf
    }

    // ------------------------- stage 3: flags u32 table (state+0x17e8) ------

    private val C0 = 0xb4b41272.toInt()
    private val CFL = intArrayOf(
        0x89e23c5f.toInt(), 0xc74c4a03.toInt(), 0xb8f43515.toInt(), 0x07297e18,
        0xf2cc1c57.toInt(), 0x292bcf40, 0xe863df66.toInt(), 0x8aa0b814.toInt(),
    )

    private fun u32tab(): IntArray {
        val t = IntArray(256)
        for (b in 0..255) {
            var v = C0
            for (i in 0..7) {
                if (b and (1 shl i) != 0) v = v xor CFL[i]
            }
            t[b] = v
        }
        return t
    }

    // ------------- stages 4/5: divisor+map (state+0x1be8) -------------------

    private val B4 = intArrayOf(0x00, 0x14, 0x28, 0x46)

    private fun divisor(body: ByteArray): ByteArray {
        val div = ByteArray(176)
        for (i in 0..15) {
            val q = i shr 2
            val b = B4[i and 3]
            val row = ByteArray(11)
            for (c in 0..3) {
                val x = (body[0x30 + 4 * c + q].toInt() xor body[0xe0 + 4 * c + q].toInt()) and 0xff
                row[c] = (x % (b + 7) and 3).toByte()
            }
            for (c in 0..3) {
                val x = (body[0xf0 + 4 * c + q].toInt() xor body[0x30 + 4 * c + q].toInt()) and 0xff
                row[4 + c] = (x % (b + 9) and 3).toByte()
            }
            for (c in 0..2) {
                val x = (body[0xc0 + 4 * c + q].toInt() xor body[0x30 + 4 * c + q].toInt()) and 0xff
                row[8 + c] = (x % (b + 5) and 3).toByte()
            }
            row.copyInto(div, 11 * i)
        }
        return div
    }

    private fun step(kb: Int): Int = when (kb) {
        1 -> 5
        0x18 -> 3
        0x24 -> 1
        else -> error("bad key byte ${kb.toString(16)}")
    }

    private fun mapKey(div: ByteArray): ByteArray {
        val km = div.copyOf()
        for (c in 0..10) {
            var acc = 0
            for (r in 0..15) {
                when (val v = km[11 * r + c].toInt() and 0xff) {
                    in 0..1 -> { km[11 * r + c] = 0x18; acc += 3 }
                    2 -> { km[11 * r + c] = 0x01; acc += 5 }
                    else -> { km[11 * r + c] = 0x24; acc += 1 }
                }
            }
            var k = 0
            while (acc > 32) {                       // exit when acc <= 0x20
                val row = (12 + 5 * k) and 0xf
                when (km[11 * row + c].toInt() and 0xff) {
                    0x01 -> { acc -= 4; km[11 * row + c] = 0x24 }
                    0x18 -> { acc -= 2; km[11 * row + c] = 0x24 }
                }
                k += 1
            }
        }
        return km
    }

    // ------------------------- stage 6: perm tables -------------------------

    private fun perms(u32t: IntArray): Pair<IntArray, IntArray> {
        val tA = NacSignTables.tA
        val tB = NacSignTables.tB
        val tC = NacSignTables.tC
        val perm1 = IntArray(256)
        val perm2 = IntArray(256)
        for (i in 0..255) {
            val t = u32t[i]
            val s = (tB[(tA[i].toInt() xor 0xa4) and 0xff].toInt() and 0xff)
            perm1[s] = t
            val u = (tC[i].toInt() xor tB[i].toInt()) and 0xff
            perm2[u] = t
        }
        return perm1 to perm2
    }

    // ----------- stage 7: keygen (544 B at state+0x2678) --------------------

    private fun keygen(body: ByteArray, kbmap: ByteArray): ByteArray {
        val t = NacSignTables
        val out = ByteArray(544)
        var acc = 0
        for (o in 0..8) {
            val chunk = t.e16[o]
            val skip = t.skip[o]
            val rowOff = 0x200 * o
            var cum = 0
            for (c in 0..15) {
                val kb = kbmap[1 + o + 11 * c].toInt() and 0xff
                val stp = step(kb)
                val rbp = skip + cum
                val i1 = (acc + rbp) % 576
                val i2 = (skip + 1 + cum + i1) % 576
                val bSum = (body[i1].toInt() + body[i2].toInt()) and 0xff
                val gi = (t.tG[c].toInt() and 0xff) + chunk
                out[gi] = bSum.toByte()
                var p1 = 0
                for (k in 0 until stp) {
                    p1 = p1 xor ((t.tbl9[rowOff + 0x20 * c + ((cum + k) and 0xf)].toInt() and 0xff))
                }
                var p2 = 0
                for (k in 0 until stp) {
                    p2 = p2 xor (body[rbp + k].toInt() and 0xff)
                }
                out[gi + 1] = (((p1 xor p2) - bSum) and 0xff).toByte()
                acc = i2
                cum += stp
            }
        }
        return out
    }

    // ----------- stage 8: matrix copy + phases B..E -------------------------

    private val FLAGS = 0xa4b51a62.toInt()          // state+0x6fec constant

    private fun phaseBCDE(body: ByteArray, kbmap: ByteArray, u32t: IntArray, state: ByteArray) {
        val t = NacSignTables
        for (j in 0..13) {
            val src = (t.mtxSrc[j] * 16).toInt()
            val dst = t.mtxDst[j].toInt()
            body.copyInto(state, 0x2678 + dst, src, src + 16)
        }
        var pos = 0
        for (j in 0..15) {                        // phase B: kb row state+0x1bf2
            val kb = kbmap[0x0a + 11 * j].toInt() and 0xff
            val s = step(kb)
            if (kb != 0x24) {
                var x = 0
                for (k in 0 until s) {
                    x = x xor ((body[0x1a0 + pos + k].toInt() and 0xff) xor
                        (t.phbT[0x20 * j + ((pos + k) and 0xf)].toInt() and 0xff))
                }
                putU32le(state, 0x1d98 + 4 * t.phbIdx[j].toInt(), FLAGS xor u32t[x])
            }
            pos += s
        }
        for (j in 0..15) {                        // phase C: kb == 0x24 of same row
            val kb = kbmap[0x0a + 11 * j].toInt() and 0xff
            if (kb == 0x24) {
                val dst = 0x1d98 + 4 * t.phbIdx[j].toInt()
                for (b in 0..3) {
                    state[dst + b] = ((state[0x27b8 + 4 * j + b].toInt() xor
                        state[0x2758 + (4 * j and 0xc) + b].toInt()) and 0xff).toByte()
                }
            }
        }
        pos = 0
        for (j in 0..15) {                        // phase D
            val kb = kbmap[11 * j].toInt() and 0xff
            val s = step(kb)
            if (kb != 0x24) {
                var x = 0
                for (k in 0 until s) {
                    x = x xor ((body[0x40 + pos + k].toInt() and 0xff) xor
                        (t.pheT[0x20 * j + ((pos + k) and 0xf)].toInt() and 0xff))
                }
                putU32le(state, 0x1c98 + 4 * t.pheIdx[j].toInt(), u32t[x])
            }
            pos += s
        }
        for (j in 0..15) {                        // phase E: kb == 0x24 rows of row B
            val kb = kbmap[11 * j].toInt() and 0xff
            if (kb == 0x24) {
                val off = j + (if (j < 5) 0 else if (j < 13) 1 else 2)
                val dst = 0x1c98 + 4 * t.pheIdx[j].toInt()
                for (b in 0..3) {
                    state[dst + b] = ((state[0x2768 + 4 * off + b].toInt() xor
                        state[0x2758 + 4 * (off and 3) + b].toInt()) and 0xff).toByte()
                }
            }
        }
        fun f(x: Int, b: Int): Int = (((x or 0xf0) + 0xf0) and FMASK[b]) and 0xff
        for (a in 0 until 0x24 step 4) {
            for (k in 0..3) {
                var w = 0
                for (b in 0..3) {
                    w = w or (((state[0x2678 + f(a + 0x24 * k + b, b)].toInt() and 0xff) xor
                        (state[0x2768 + 0x24 * k + a + b].toInt() and 0xff)) shl (8 * b))
                }
                putU32le(state, 0x25d8 + 4 * (a + k), w)
            }
        }
        var rcx = 7; var rdx = 0; var rsi = 2
        for (i in 0..15) {
            val r8 = 2 * i
            val r9 = (rcx and 0xf) + 0xa1 - (r8.inv() and 2)
            val idx1 = (r9 and 0x2f) xor 0x231
            val idx2 = (((rsi and 0xf) + ((rdx and 6) xor 2) + 0x1d) and 0xef) xor 0x23
            val bl = (state[0x2678 + idx1].toInt() xor state[0x2678 + (r9 xor 0xa1)].toInt()) and 0xff
            val b2 = (state[0x2678 + (idx2 or 0x210)].toInt() xor state[0x2748 + idx2].toInt()) and 0xff
            state[0x2668 + i] = (bl - b2 and 0xff).toByte()
            rcx += 3; rdx += 6; rsi += 0xb
        }
    }

    private val FMASK = intArrayOf(0xec, 0xed, 0xee, 0xff)

    // ----------- stage 9: vecA/vecB + 16 position rounds --------------------

    private val C68 = 0xa4b51a62.toInt()            // scatter-mutation index const
    private val MUT_MASK = 0xeffef7ef.toInt()

    private fun scatterMutated(body: ByteArray, u32t: IntArray): Pair<Int, ByteArray> {
        val (n, scat) = scatter(body)
        val buf = scat.copyOf()
        var d = 0xb0
        for (i in 0..255) {
            val idx = (((u32t[i] xor C0) xor C68).toLong() and MUT_MASK.toLong() and 0xffffffffL)
                .rem(n.toLong()).toInt()
            buf[idx] = (d xor 0xb0).toByte()
            val r10 = (2 * (i + 1)) and 0xff
            d = (((0xa0 - (r10 and 0x60)) or 0x11) + i) and 0xff
        }
        return n to buf
    }

    private fun vecABMut(body: ByteArray, u32t: IntArray): Quad<Int, ByteArray, ByteArray, ByteArray> {
        val t = NacSignTables
        val (n, scat) = scatterMutated(body, u32t)
        val vecA = ByteArray(n)
        val vecB = ByteArray(n)
        for (i in 0 until n) {
            val s = scat[i].toInt() and 0xff
            vecA[i] = ((t.t243c50[s].toInt() xor t.t243d50[s].toInt()) and 0xff).toByte()
            val pre = ((i.inv() shr 1) and 0xe6) + (i shr 2) + 0xd
            vecB[i] = ((pre and 0xff) xor
                (t.tB[(t.t243b50[s].toInt() xor 0xa4) and 0xff].toInt() and 0xff) xor 0x82).and(0xff)
                .toByte()
        }
        return Quad(n, scat, vecA, vecB)
    }

    private class Quad<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D) {
        operator fun component1(): A = first
        operator fun component2(): B = second
        operator fun component3(): C = third
        operator fun component4(): D = fourth
    }

    private fun rounds(state: ByteArray) {
        val t2 = NacSignTables.t2Big
        val perm2u = IntArray(256) { u32At(state, 0x21d8 + 4 * it) }
        for (p in 0..15) {
            val r13 = 4 * (p and 3) or (p shr 2)
            val seedA = ((((state[0x2888 + r13].toInt() xor state[0x2878 + r13].toInt()) and 0xff) +
                (state[0x2888 + r13].toInt() xor state[0x2748 + r13].toInt())) and 0xff) xor 0x38
            var r8 = 0xa71f8a3b.toInt()
            val baseW = 0x2898 + 0x1000 * (p and 3) + 0x400 * (p shr 2)
            val t2b = 0x1400 * (p and 3) + 0x500 * (p shr 2)
            for (j in 0 until 128) {
                val x1 = t2[t2b + 2 * j].toInt() and 0xff
                putU32le(state, baseW + 8 * j,
                    (r8 + 0x4fd1152d) xor perm2u[x1 xor seedA] xor 0x12501000)
                val x2 = t2[t2b + 2 * j + 1].toInt() and 0xff
                putU32le(state, baseW + 8 * j + 4, r8 xor perm2u[x2 xor seedA] xor 0x12501000)
                r8 += 0x605dd5a6
            }
            // (the per-round vecout is recomputed by genBufs from the same table)
        }
    }

    // ----------- 16 generator buffers (sig_init.gen_bufs) -------------------

    private fun genBufs(kg: ByteArray, vecA: ByteArray): Array<ByteArray> {
        val t2 = NacSignTables.t2Big
        val out = arrayOfNulls<ByteArray>(16)
        for (iter in 0..15) {
            val q = iter shr 2
            val r = iter and 3
            val rbx = 13 * q + 4 * r
            val sel = rbx and 0xf
            val raxPre = (rbx and 0xf) + ((0x1e - 2 * rbx) and 0x16) + 0x15
            val i1 = raxPre xor 0x2b
            val i2 = (raxPre and 0x2f) xor 0xfb
            val seed = (((kg[i1].toInt() xor kg[0x140 + i2].toInt()) and 0xff) -
                ((kg[0x140 + i2].toInt() xor kg[i2].toInt()) and 0xff) and 0xff) xor 0x59
            val entry = q + 4 * r
            val tblOff = 0x9000 + sel * 256
            val buf = ByteArray(vecA.size)
            for (i in vecA.indices) {
                buf[i] = ((((i xor 0x73) + 0xc5) and 0xff) xor
                    (t2[tblOff + ((vecA[i].toInt() and 0xff) xor seed)].toInt() and 0xff) xor 0x89)
                    .and(0xff).toByte()
            }
            out[entry] = buf
        }
        @Suppress("UNCHECKED_CAST")
        return out as Array<ByteArray>
    }

    // ----------- per-run init: RS32, rec0, r70ab (sig_init.rs_init) ---------

    private const val N = 2571
    private val MASK_IDX = 0xeffef7ef.toInt()

    /** RS byte template: perm1[c] ^ PDE[k] -> masked index -> BUF lookup. */
    private fun rsIdxVal(c: Int, k: Int, state: ByteArray, buf: ByteArray): Int {
        val w = u32At(state, 0x1dd8 + 4 * c) xor u32At(state, 0x1d98 + 4 * k)
        // w & MASK_IDX is an unsigned u32 in the model — keep it unsigned here too
        var idx = (w.toLong() and MASK_IDX.toLong() and 0xffffffffL)
        if (idx >= N) idx %= N
        val i = idx.toInt()
        return ((((i and 0xff) xor 0xf3) + 0x45) and 0xff) xor
            (buf[i].toInt() and 0xff) xor 0x89
    }

    private fun rec0Of(chain1: IntArray): ByteArray =
        ByteArray(17) { j -> (((chain1[(3 + 7 * j) % 16] + j) and 0xff) xor 0x58).toByte() }

    /** per r8: (tsel, k, dst); buffer = generator entry r8+4. */
    private val LOOP = arrayOf(
        intArrayOf(4, 13, 16), intArrayOf(1, 7, 11), intArrayOf(14, 14, 13),
        intArrayOf(11, 1, 14), intArrayOf(8, 11, 9), intArrayOf(5, 4, 0),
        intArrayOf(2, 10, 5), intArrayOf(15, 0, 12), intArrayOf(12, 15, 8),
        intArrayOf(9, 12, 3), intArrayOf(6, 2, 10), intArrayOf(3, 3, 2),
    )

    /** single blocks: (dst, c, k, entry). */
    private val SINGLES = arrayOf(
        intArrayOf(1, 0, 5, 0), intArrayOf(4, 13, 6, 1),
        intArrayOf(6, 10, 9, 2), intArrayOf(15, 7, 8, 3),
    )

    private fun rsInit(
        state: ByteArray,
        bufs: Array<ByteArray>,
        chain1: IntArray,
    ): Triple<IntArray, ByteArray, Int> {
        val rs = IntArray(32)
        for ((r8, l) in LOOP.withIndex()) {
            val (tsel, k, dst) = listOf(l[0], l[1], l[2])
            rs[dst] = rsIdxVal(chain1[tsel], k, state, bufs[r8 + 4])
        }
        for (s in SINGLES) {
            val (dst, c, k, entry) = listOf(s[0], s[1], s[2], s[3])
            rs[dst] = rsIdxVal(chain1[c], k, state, bufs[entry])
        }
        val r0 = rec0Of(chain1)
        // r70ab from chain1 + vec16 (0x17a297d block)
        var al = ((chain1[0] xor 0xf2) + (state[0x2668 + 2].toInt() and 0xff) -
            (state[0x2668].toInt() and 0xff)) and 0xff
        al = al xor chain1[1]
        var cl = (chain1[2] - (state[0x2668 + 11].toInt() and 0xff)) and 0xff
        cl = (cl + al) and 0xff
        cl = cl xor (state[0x2668 + 12].toInt() and 0xff)
        cl = (cl - chain1[3]) and 0xff
        return Triple(rs, r0, cl xor 0x9b)
    }

    // ----------- soup57/soup80 (0x17a2f1a-0x17a2fc5) ------------------------

    private fun soup(
        state: ByteArray,
        chain1: IntArray,
        sp80In: Int,
        r10b: Int,
        r11b: Int,
    ): Pair<Int, Int> {
        val g = NacSignTables.region6f98
        val c = chain1
        val dl = ((c[8] xor 5) + (g[9].toInt().inv() and 0xff) + (g[8].toInt() and 0xff)) and 0xff
        var cl = ((dl * 2 + 2).inv() and 0xcc) + dl + 0x9b and 0xff
        cl = (cl xor c[9]) xor 0x99
        var r8b = sp80In
        r8b = (r8b - (g[13].toInt() and 0xff)) and 0xff
        r8b = (r8b + cl) and 0xff
        r8b = r8b xor (g[15].toInt() and 0xff)
        r8b = (r8b + (c[11] xor 0x7f)) and 0xff
        r8b = (r8b + 0x81) and 0xff
        var r11 = ((r11b xor 0xf4) - (g[6].toInt() and 0xff) + (g[1].toInt() and 0xff)) and 0xff
        r11 = (r11 xor c[5]) and 0xff
        var r9 = (c[6] + 0x80) and 0xff
        r9 = (r9 - (g[3].toInt() and 0xff)) and 0xff
        r9 = (r9 + r11) and 0xff
        r9 = r9 xor (g[14].toInt() and 0xff)
        r9 = (r9 + 0x80) and 0xff
        r9 = (r9 - r10b) and 0xff
        return r9 to r8b
    }

    // ----------- threshold cipher tail (sig_tail.py) ------------------------

    private class TailState(rs32: IntArray, rec0: ByteArray, var r70ab: Int, sp20Consts: IntArray) {
        val rs = rs32.copyOf()
        val rec = IntArray(17 * 9)
        val c97c = sp20Consts[0]
        val c97d = sp20Consts[1]
        val c97f = sp20Consts[2]
        val c9a2 = sp20Consts[3]

        init {
            for (i in 0..16) rec[i] = rec0[i].toInt() and 0xff
        }
    }

    /** run-start feedback (0x17a2eac): bl = a ^ b ^ RS[1] -> RS[7]; RS[3] ^= bl ^ 0x38. */
    private fun runstartFeedback(ts: TailState, a: Int, b: Int) {
        val bl = (a and 0xff) xor (b and 0xff) xor ts.rs[1]
        ts.rs[7] = bl
        ts.rs[3] = ts.rs[3] xor bl xor 0x38
    }

    private fun mix(kg: (Int) -> Int, rbp: Int, rs: IntArray, al: Int, bl: Int): Map<String, Int> {
        val r = rs
        val g = { j: Int -> kg(rbp + j) }
        val x = { a: Int, b: Int -> (a xor b) and 0xff }
        return mapOf(
            "dl1" to x(x(g(0x0e) + g(0x0f), r[0x0b]), 0x38),
            "dil1" to x(g(0x0c) + g(0x0d), r[0x0a]),
            "dil1x" to (x(g(0x0c) + g(0x0d), r[0x0a]) xor 0x38),
            "r8b" to x(x(g(0x06) + g(0x07), r[0x10]), 0x38),
            "al" to x(x(g(0x04) + g(0x05), r[0x00]), 0x38),
            "b6" to x(x(g(0x00) + g(0x01), r[0x08]), 0x38),
            "bl" to x(x(bl, al), (g(0x14) + g(0x15)) and 0xff),
            "r12b" to x(x(g(0x1a) + g(0x1b), r[0x04]), 0x38),
            "r11b" to x(x(g(0x12) + g(0x13), r[0x09]), 0x38),
            "cl3" to x(x(g(0x18) + g(0x19), r[0x0d]), 0x38),
            "edi2" to x(x(g(0x08) + g(0x09), r[0x06]), 0x38),
            "r10b" to x(x(g(0x16) + g(0x17), r[0x05]), 0x38),
            "r13mid" to x(x(g(0x10) + g(0x11), r[0x02]), 0x38),
            "dl2" to x(x(g(0x1e) + g(0x1f), r[0x0f]), 0x38),
            "bpl" to x(x(g(0x1c) + g(0x1d), r[0x0c]), 0x38),
            "sp1f8" to x(x(g(0x0a) + g(0x0b), r[0x01]), 0x38),
            "sp48" to x(x(g(0x02) + g(0x03), r[0x0e]), 0x38),
        )
    }

    // round constants (rc-xor at 0x17a347b): (ecx, ebx, eax, edx) per r12.
    private val RC = arrayOf(
        intArrayOf(0x6db4d78c, 0x39c17123, 0x10000800, 0x7d2b7a3d),
        intArrayOf(0x91c9e17b.toInt(), 0x43c27516, 0x8833bd3f.toInt(), 0x2be7e3f8),
        intArrayOf(0xc5c95c16.toInt(), 0x3600f2eb, 0x4b150d7f, 0x1e1561a0),
        intArrayOf(0x9d272c48.toInt(), 0xff511567.toInt(), 0xf52b2b67.toInt(), 0xc974d62c.toInt()),
        intArrayOf(0xc21d8753.toInt(), 0x533fd05b, 0x253d787c, 0xc1481826.toInt()),
        intArrayOf(0xd7915485.toInt(), 0xf959e065.toInt(), 0x3e03b158, 0x07d5db45),
        intArrayOf(0xfd338a1f.toInt(), 0x8a4a0677.toInt(), 0xf2cc1c47.toInt(), 0x0a536e6c),
        intArrayOf(0x935aec40.toInt(), 0x596dbe37, 0x647bccd7, 0x6c2bb938),
        intArrayOf(0x6cede063, 0x23361c77, 0xa0cee083.toInt(), 0x4b8b7e10),
    )

    /** r14b after mixing: constant per r12; record-window byte offset in the export D formula. */
    private val XR14 = intArrayOf(0, 1, 1, 2, 2, 2, 5, 3, 3)

    /** 17-loop byte-table pointers (sig_tail._BT_PTRS) — slices of t2Big (base 0x2279f8). */
    private val BT_PTRS = intArrayOf(
        0x22b9f8, 0x22bef8, 0x22c3f8, 0x22c8f8, 0x22cdf8, 0x22d2f8, 0x22d7f8, 0x22dcf8,
        0x22e1f8, 0x22e6f8, 0x22ebf8, 0x22f0f8, 0x22f5f8, 0x22faf8, 0x22fff8, 0x2304f8,
        0x22f9f8, 0x22fef8, 0x2303f8, 0x2308f8, 0x227df8, 0x2282f8, 0x2287f8, 0x228cf8,
        0x2291f8, 0x2296f8, 0x229bf8, 0x22a0f8, 0x22a5f8, 0x22aaf8, 0x22aff8, 0x22b4f8,
        0x22a9f8, 0x22aef8, 0x22b3f8, 0x22b8f8, 0x22bdf8, 0x22c2f8, 0x22c7f8, 0x22ccf8,
        0x22d1f8, 0x22d6f8, 0x22dbf8, 0x22e0f8, 0x22e5f8, 0x22eaf8, 0x22eff8, 0x22f4f8,
        0x22e9f8, 0x22eef8, 0x22f3f8, 0x22f8f8, 0x22fdf8, 0x2302f8, 0x2307f8, 0x227cf8,
        0x2281f8, 0x2286f8, 0x228bf8, 0x2290f8, 0x2295f8, 0x229af8, 0x229ff8, 0x22a4f8,
        0x2299f8, 0x229ef8, 0x22a3f8, 0x22a8f8, 0x22adf8, 0x22b2f8, 0x22b7f8, 0x22bcf8,
        0x22c1f8, 0x22c6f8, 0x22cbf8, 0x22d0f8, 0x22d5f8, 0x22daf8, 0x22dff8, 0x22e4f8,
        0x22d9f8, 0x22def8, 0x22e3f8, 0x22e8f8, 0x22edf8, 0x22f2f8, 0x22f7f8, 0x22fcf8,
        0x2301f8, 0x2306f8, 0x227bf8, 0x2280f8, 0x2285f8, 0x228af8, 0x228ff8, 0x2294f8,
        0x2289f8, 0x228ef8, 0x2293f8, 0x2298f8, 0x229df8, 0x22a2f8, 0x22a7f8, 0x22acf8,
        0x22b1f8, 0x22b6f8, 0x22bbf8, 0x22c0f8, 0x22c5f8, 0x22caf8, 0x22cff8, 0x22d4f8,
        0x22c9f8, 0x22cef8, 0x22d3f8, 0x22d8f8, 0x22ddf8, 0x22e2f8, 0x22e7f8, 0x22ecf8,
        0x22f1f8, 0x22f6f8, 0x22fbf8, 0x2300f8, 0x2305f8, 0x227af8, 0x227ff8, 0x2284f8,
    )

    private fun btabAt(t2: ByteArray, r12: Int, tsel: Int, idx: Int): Int {
        val ptr = BT_PTRS[r12 * 16 + tsel] - 0x2279f8
        return t2[ptr + idx].toInt() and 0xff
    }

    /** One cipher round; returns sp20 (only meaningful for r12 == 8). Mutates ts. */
    private fun cipherRound(ts: TailState, state: ByteArray, r12: Int): Int {
        val t = NacSignTables
        val t2 = t.t2Big
        val kg = { off: Int -> state[0x2678 + off].toInt() and 0xff }
        val rbp = t.sel[r12].toInt()
        val rs = ts.rs
        val al = rs[3]
        val bl = rs[7]
        val m = mix(kg, rbp, rs, al, bl)
        val utab = { slot: Int, idx: Int -> t.utab[r12][slot][idx] }
        val ebp = utab(1, m["r12b"]!!) xor utab(0, m["sp1f8"]!!)
        var eax = utab(1, m["al"]!!) xor utab(0, m["r11b"]!!) xor
            utab(2, m["r10b"]!!) xor utab(3, m["bpl"]!!)
        var ecx = utab(3, m["dl2"]!!) xor utab(2, m["edi2"]!!)
        val edi = utab(5, m["dl1"]!!) xor utab(4, m["r8b"]!!)
        val r10 = utab(5, m["bl"]!!) xor utab(4, m["b6"]!!)
        var ebx = utab(7, m["sp48"]!!) xor utab(6, m["cl3"]!!)
        var edx = utab(7, m["r13mid"]!!) xor utab(6, m["dil1x"]!!)
        ecx = ecx xor ebp xor RC[r12][0]
        ebx = ebx xor edi xor RC[r12][1]
        eax = eax xor RC[r12][2]
        edx = edx xor r10 xor RC[r12][3]
        // export
        val x14 = XR14[r12]
        val d = ts.r70ab xor ts.rec[17 * x14 + 16] xor ts.rec[17 * x14 + 8] xor
            m["dil1"]!! xor ((ebx shr 16) and 0xff) xor 0x5c
        val exp = IntArray(17)
        exp[0] = ((ecx shr 16) and 0xff) xor d
        exp[1] = ebx and 0xff
        exp[2] = (ecx shr 8) and 0xff
        exp[3] = (eax shr 24) and 0xff
        exp[4] = (edx shr 8) and 0xff
        exp[5] = (ebx shr 8) and 0xff
        exp[6] = (ebx shr 16) and 0xff
        exp[7] = (edx shr 16) and 0xff
        exp[8] = d
        exp[9] = (eax shr 8) and 0xff
        exp[10] = eax and 0xff
        exp[11] = (ecx shr 24) and 0xff
        exp[12] = edx and 0xff
        exp[13] = (edx shr 24) and 0xff
        exp[14] = (ebx shr 24) and 0xff
        exp[15] = (eax shr 16) and 0xff
        exp[16] = ecx and 0xff
        for (i in 0..14) rs[17 + i] = exp[i]
        var sp20 = 0
        if (r12 < 8) {
            for (i in 0..16) ts.rec[17 * (r12 + 1) + i] = exp[i]
            for (i in 0..16) {
                if (i == 8) continue
                var v = btabAt(t2, r12, t.ts17[i].toInt(), exp[i] xor (if (i == 0) d else 0))
                if (t.md17[i].toInt() == 3) v = v xor 0x38
                rs[t.md17[i].toInt()] = v
            }
            val bl2 = rs[11] xor rs[4] xor ts.r70ab xor rs[1] xor 0x64
            rs[7] = bl2
            rs[3] = rs[3] xor bl2
        } else {
            var v = exp[12] xor 0x1c
            v = (v - ts.c97c + ts.c9a2) and 0xff
            v = v xor exp[13]                          // 'xor %dil'
            v = (v + ((ts.c97f - exp[14]) and 0xff)) and 0xff  // 'sub %bl'
            v = v xor ts.c97d
            v = (v + exp[15]) and 0xff                 // 'add %al'
            sp20 = v
        }
        for (i in 0..16) ts.rec[i] = exp[i]
        return sp20
    }

    // ----------- staging from the generator soup (sig_hand) -----------------

    private const val MASK6FE8 = 0x10010810
    private const val SP28 = 0x40

    private fun stagingFromSoup(
        state: ByteArray,
        vecB: ByteArray,
        n: Int,
        sp20: Int,
    ): ByteArray {
        val t = NacSignTables
        val t2 = t.t2Big
        val stg = ByteArray(16)
        for (i in 0..15) {
            val idxP = (t.t2Sel[i] shr 2).toInt()      // phaseD/E u32 index (<= 0xff)
            var ebx = state[0x7001 + t.t1Sel[i].toInt()].toInt() and 0xff
            if (i == 10) ebx = ebx xor (state[0x7009].toInt() and 0xff)
            val rdx = (0x100 * (i and 3)) or ebx
            val r9 = ebx * 0x4fd1152d + 0x890f6097.toInt()
            val r10 = u32At(state, 0x1c98 + 4 * idxP)
            val p2u = u32At(state, 0x21d8 + 4 * (state[0x6f98 + i].toInt() and 0xff))
            val edi: Int
            val ebp: Int
            when (i) {
                in 0..3 -> { edi = u32At(state, 0x2898 + 4 * rdx); ebp = p2u }
                4, 5 -> { edi = u32At(state, 0x3898 + 4 * rdx); ebp = p2u }
                6, 7 -> { edi = p2u; ebp = u32At(state, 0x3898 + 4 * rdx) }
                8, 9 -> { edi = u32At(state, 0x4898 + 4 * rdx); ebp = p2u }
                10 -> { edi = u32At(state, 0x21d8 + 4 * ebx); ebp = u32At(state, 0x21d8) }
                11 -> { edi = p2u; ebp = u32At(state, 0x4898 + 4 * rdx) }
                else -> { edi = u32At(state, 0x5898 + 4 * rdx); ebp = p2u }
            }
            val ecx = r10 xor 0x4b2270b0
            val b0 = MASK6FE8 and edi
            val r12v = ecx and MASK6FE8
            val r8v = MASK6FE8 and ebp
            val out: Int
            if (i == 10) {
                // al source captured live = st[0x7009] ^ idx (head xor at 0x17a374a)
                var al = (state[0x7009].toInt() xor
                    state[0x7001 + t.t1Sel[10].toInt()].toInt()) and 0xff
                al = (al xor sp20) and 0xff
                val r10x = u32At(state, 0x5098 + 4 * ebx)
                val eax = u32At(state, 0x21d8 + 4 * al) xor r10x xor
                    u32At(state, 0x21d8 + 4 * (sp20 and 0xff)) xor r9 xor 0x6dafefff
                val ecx2 = u32At(state, 0x21d8 + 4 * SP28)
                val edi2 = edi xor ebp xor r10 xor b0 xor r8v xor r12v xor ecx2 xor eax
                out = edi2 xor (((eax xor ecx2) xor 0x4b2270b0) and MASK6FE8)
            } else {
                val r15n = MASK6FE8 and (r9 xor 0x268d9f4f)
                val edi2 = edi xor r15n
                val ebp2 = ebp xor r9 xor ecx xor edi2
                out = (b0 xor r12v xor ebp2 xor r8v) xor 0x268d9f4f
            }
            val v = (out.toLong() and 0xffffffffL) % n
            stg[i] = (((v shr 2).toInt() xor (vecB[v.toInt()].toInt() and 0xff) xor 0x71) and 0xff)
                .toByte()
        }
        return stg
    }

    // ----------- final formula (0x17a3f80) ----------------------------------

    private fun finalFormula(stg: ByteArray, state: ByteArray): ByteArray {
        val t = NacSignTables
        val out = ByteArray(16)
        for (i in 0..15) {
            val sel = state[0x6fd8 + i].toInt() and 0xff
            val b = t.fin[sel].toInt()                 // u64 <= 0x1ff (bounds-checked)
            val a = stg[i].toInt() and 0xff
            val r = when {
                a == 0 -> b and 0xff
                b == a -> 0
                else -> keygenCommon1(a, b)
            }
            out[i] = (((r - (state[0x6898 + 0x100 * sel + a].toInt() and 0xff) + 0xeb) and 0xff)
                xor 0x7f).toByte()
        }
        return out
    }

    // ----------- keygen_common1 (0x179dd60) + fold quirks -------------------

    /** keygen_common1 @0x179dd60: rdi=a, rsi=b -> al. */
    private fun keygenCommon1(a: Int, b: Int): Int {
        val t = NacSignTables
        val v1 = (t.k1[a].toInt() xor 0xa4) and 0xff
        val v2 = (t.k1[b].toInt() xor 0xa4) and 0xff
        val t1 = if (v1 < 0x1b) 0x100 else 0
        val t2 = if (v2 < 0x1b) 0x100 else 0
        val r8 = ((if (v1 >= 0x1b) 0x100 else 0) + v1 - 0x100) xor 0xff
        val i1 = v2 + t2 + r8
        check(i1 in 0 until 0x200) { "keygen_common1: i1 out of range" }
        val v3 = (t.k2[i1].toInt() xor 0xa4) and 0xff
        val t3 = if (v3 < 0x49) 0x100 else 0
        val i2 = t3 + v1 + t1 + v3 - 0x64
        check(i2 in 0 until 0x200) { "keygen_common1: i2 out of range" }
        return t.k3[i2].toInt() and 0xff
    }

    /** caller-side fold quirks (0x179dd60 call sites). */
    private fun foldStep(prev: Int, x: Int): Int = when {
        prev == 0 -> x
        x == 0 -> prev
        prev == x -> 0
        else -> keygenCommon1(x, prev)
    }

    // ----------- little-endian state helpers --------------------------------

    private fun u32At(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xff) or
            ((b[off + 1].toInt() and 0xff) shl 8) or
            ((b[off + 2].toInt() and 0xff) shl 16) or
            ((b[off + 3].toInt() and 0xff) shl 24)

    private fun putU32le(b: ByteArray, off: Int, v: Int) {
        b[off] = v.toByte()
        b[off + 1] = (v shr 8).toByte()
        b[off + 2] = (v shr 16).toByte()
        b[off + 3] = (v shr 24).toByte()
    }

    private fun putU64le(b: ByteArray, off: Int, v: Long) {
        for (i in 0 until 8) b[off + i] = (v shr (8 * i)).toByte()
    }
}
