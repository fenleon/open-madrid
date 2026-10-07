package dev.fenn.imessage.registration

/**
 * Kotlin transcription of the ClearADI provisioning-cipher path (librust_lib_bluebubbles,
 * the OpenBubbles white-box CoreADI). Address citations refer to that .so. Quirks of the
 * white-box network (rotated round outputs, dead constants, phase-2 pipeline scatter,
 * OR-colliding spim_map bits) are reproduced exactly — they are load-bearing.
 *
 * Ported and byte-exact against the live library: decodeSpim, ingest, docrypt, encrypt,
 * encrypt_ingest, encsec, spim_map_signature, init_session (all three phases), decryptPTM
 * (0x17ffb50: initial key-mix head, phase A, 4.3 S-box tail, 4.4 key schedule, K0–K4).
 */
internal object ClearAdiProvision {

    // ---- helpers -------------------------------------------------------------

    private fun u32le(b: ByteArray, i: Int): Int =
        (b[i].toInt() and 0xff) or
            ((b[i + 1].toInt() and 0xff) shl 8) or
            ((b[i + 2].toInt() and 0xff) shl 16) or
            ((b[i + 3].toInt() and 0xff) shl 24)

    private fun putU32le(b: ByteArray, i: Int, v: Int) {
        b[i] = v.toByte()
        b[i + 1] = (v ushr 8).toByte()
        b[i + 2] = (v ushr 16).toByte()
        b[i + 3] = (v ushr 24).toByte()
    }

    /** one byte of a word, position 0 = LSB. */
    private fun byteOf(x: Int, n: Int): Int = (x ushr (8 * n)) and 0xff

    private fun words(b16: ByteArray): IntArray = IntArray(4) { u32le(b16, 4 * it) }

    private fun fromWords(w: IntArray): ByteArray = ByteArray(16).also { for (i in 0 until 4) putU32le(it, 4 * i, w[i]) }

    private fun bswap(x: Int): Int = Integer.reverseBytes(x)

    private fun beWord(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xff) shl 24) or ((b[off + 1].toInt() and 0xff) shl 16) or
            ((b[off + 2].toInt() and 0xff) shl 8) or (b[off + 3].toInt() and 0xff)

    private fun const16(vaddr: Int): ByteArray = ClearAdiTables.consts16(vaddr)
    private fun wordTable(vaddr: Int): IntArray = ClearAdiTables.wordTable(vaddr)
    private fun byteTable(vaddr: Int): ByteArray = ClearAdiTables.byteTable(vaddr)

    // ---- shared primitives -----------------------------------------------------

    private val tJoinB0 = wordTable(0x256ec0)
    private val tJoinB1 = wordTable(0x256ac0)
    private val tJoinB2 = wordTable(0x2566c0)
    private val tJoinB3 = wordTable(0x2562c0)

    private fun join(a: Int, b: Int, c: Int, d: Int): Int =
        tJoinB0[byteOf(a, 0)] xor tJoinB1[byteOf(b, 1)] xor
            tJoinB2[byteOf(c, 2)] xor tJoinB3[byteOf(d, 3)]

    private val tJ2I = wordTable(0x2556c0)
    private val tJ2B1 = wordTable(0x255ac0)
    private val tJ2B2 = wordTable(0x2552c0)
    private val tJ2B3 = wordTable(0x255ec0)

    private fun join2(i: Int, a: Int, b: Int, c: Int): Int =
        tJ2I[i and 0xff] xor tJ2B1[byteOf(a, 1)] xor tJ2B2[byteOf(b, 2)] xor tJ2B3[byteOf(c, 3)]

    private val tAlaB0 = wordTable(0x25b2c0)
    private val tAlaB1 = wordTable(0x25b6c0)
    private val tAlaB2 = wordTable(0x25bac0)
    private val tAlaB3 = wordTable(0x25bec0)

    private fun ala(x: Int): Int =
        tAlaB0[byteOf(x, 0)] xor tAlaB1[byteOf(x, 1)] xor
            tAlaB2[byteOf(x, 2)] xor tAlaB3[byteOf(x, 3)]

    private val tOgB0 = wordTable(0x25f2c0)
    private val tOgB1 = wordTable(0x25f6c0)
    private val tOgB2 = wordTable(0x25eac0)
    private val tOgB3 = wordTable(0x25eec0)

    private fun outgen(x: Int): Int =
        tOgB0[byteOf(x, 0)] xor tOgB1[byteOf(x, 1)] xor
            tOgB2[byteOf(x, 2)] xor tOgB3[byteOf(x, 3)]

    private val tIngB0 = wordTable(0x2622c0)
    private val tIngB1 = wordTable(0x262ac0)
    private val tIngB2 = wordTable(0x2626c0)
    private val tIngB3 = wordTable(0x262ec0)

    /** ingest: source words come from the block in [+8,+0xc,+0,+4] order with fixed consts. */
    private fun ingest(block16: ByteArray): IntArray {
        val w = words(block16)
        val src = intArrayOf(
            w[2] xor 0x54F532EA.toInt(), w[3] xor 0x2A1BFBF2.toInt(),
            w[0] xor 0x61D5F556, w[1] xor 0x07D1FC1D,
        )
        return IntArray(4) { k ->
            tIngB0[byteOf(src[k], 0)] xor tIngB1[byteOf(src[k], 1)] xor
                tIngB2[byteOf(src[k], 2)] xor tIngB3[byteOf(src[k], 3)]
        }
    }

    // ---- decodeSpim (0x17fc780) --------------------------------------------------

    private val dspimKx = byteArrayOf(
        0x86.toByte(), 0x81.toByte(), 0x9a.toByte(), 0xcb.toByte(),
        0x16.toByte(), 0x05.toByte(), 0x2f.toByte(), 0x64.toByte(),
        0x3d.toByte(), 0xce.toByte(), 0x68.toByte(), 0x39.toByte(),
        0xd5.toByte(), 0xd9.toByte(), 0x82.toByte(), 0x53.toByte(),
    )
    private val dspimT3 = byteTable(0x2597c0) // byte position 4k
    private val dspimT2 = byteTable(0x2596c0) // 4k+1
    private val dspimT1 = byteTable(0x2599c0) // 4k+2
    private val dspimT4 = byteTable(0x2598c0) // 4k+3
    private val dspimC1 = const16(0x1a5b10)
    private val dspimChainConst = const16(0x1a3e80)
    private val dspimC2Init = const16(0x1a2a00)
    private val dspimC3 = const16(0x1a4760)
    private val dspimRc = listOf(
        0x1a4750, 0x1a2780, 0x1a3770, 0x1a5290, 0x1a2220,
        0x1a5550, 0x1a4410, 0x1a5b20, 0x1a57f0,
    ).map { const16(it) }

    fun decodeSpim(inp: ByteArray): ByteArray {
        val out = ByteArray(240)
        var c2 = dspimC2Init.copyOf()
        for (blk in 0 until 15) {
            val ib = inp.copyOfRange(blk * 16, blk * 16 + 16)
            val w = IntArray(4)
            for (k in 0 until 4) {
                val b0 = ib[4 * k].toInt() and 0xff xor (dspimKx[4 * k].toInt() and 0xff)
                val b1 = ib[4 * k + 1].toInt() and 0xff xor (dspimKx[4 * k + 1].toInt() and 0xff)
                val b2 = ib[4 * k + 2].toInt() and 0xff xor (dspimKx[4 * k + 2].toInt() and 0xff)
                val b3 = ib[4 * k + 3].toInt() and 0xff xor (dspimKx[4 * k + 3].toInt() and 0xff)
                w[k] = ((dspimT3[b0].toInt() and 0xff) shl 24) or
                    ((dspimT2[b1].toInt() and 0xff) shl 16) or
                    ((dspimT1[b2].toInt() and 0xff) shl 8) or
                    (dspimT4[b3].toInt() and 0xff)
            }
            val c1w = words(dspimC1)
            var state = IntArray(4) { w[it] xor c1w[it] }
            for (r in 0 until 9) {
                val rcw = words(dspimRc[r])
                val new = IntArray(4)
                for (i in 0 until 4) {
                    new[(i + 1) and 3] = join(state[i], state[(i + 1) and 3], state[(i + 2) and 3], state[(i + 3) and 3]) xor rcw[i]
                }
                state = new
            }
            val cw3 = words(dspimC3)
            val c2w = words(c2)
            val outw = IntArray(4)
            for (j in 1..4) {
                val k = j and 3
                outw[k] = join2(state[j - 1], state[k], state[(k + 1) and 3], state[(k + 2) and 3]) xor
                    cw3[j - 1] xor c2w[k]
            }
            fromWords(outw).copyInto(out, blk * 16)
            val cb = dspimChainConst.copyOf()
            val wb = fromWords(w)
            for (i in 0 until 16) cb[i] = (cb[i].toInt() xor wb[i].toInt()).toByte()
            c2 = cb
        }
        return out
    }

    // ---- docrypt (0x17ff550) -------------------------------------------------------

    private val tDocB0 = wordTable(0x2632c0)
    private val tDocB1 = wordTable(0x263ec0)
    private val tDocB2 = wordTable(0x2636c0)
    private val tDocB3 = wordTable(0x263ac0)
    private val tDocfB0 = wordTable(0x2612c0)
    private val tDocfB1 = wordTable(0x2616c0)
    private val tDocfB2 = wordTable(0x261ac0)
    private val tDocfB3 = wordTable(0x261ec0)
    private val tDocgB0 = byteTable(0x260ec0)
    private val tDocgB1 = byteTable(0x260fc0)
    private val tDocgB2 = byteTable(0x2610c0)
    private val tDocgB3 = byteTable(0x2611c0)
    private val docRc = listOf(
        0x1a31d0, 0x1a19a0, 0x1a5b40, 0x1a31e0, 0x1a1f70,
        0x1a5580, 0x1a31f0, 0x1a09a0, 0x1a3200,
    ).map { const16(it) }
    private val docC1 = const16(0x1a1bf0)
    private val docC2 = const16(0x1a2a20)
    private val docC3 = const16(0x1a3c60)

    /** keys: K0..K3 = 0x30-byte buffers (+0x24 outgen word), K4 = 16 bytes. io: 4 words. */
    internal fun docrypt(block16: ByteArray, keys: List<ByteArray>, io: IntArray): Pair<IntArray, IntArray> {
        val t = ingest(block16)
        val ks = intArrayOf(
            outgen(u32le(keys[1], 0x24)), outgen(u32le(keys[2], 0x24)),
            outgen(u32le(keys[3], 0x24)), outgen(u32le(keys[0], 0x24)),
        )
        val ioNew = intArrayOf(
            t[2] xor u32le(docC1, 8), t[3] xor u32le(docC1, 12),
            t[0] xor u32le(docC1, 0), t[1] xor u32le(docC1, 4),
        )
        var s = IntArray(4) { i -> t[i] xor u32le(docC2, 4 * i) xor ks[i] }
        for (r in 0 until 9) {
            val rcw = words(docRc[r])
            val new = IntArray(4)
            for (i in 0 until 4) {
                val kw = u32le(keys[(i - r) and 3], 0x20 - 4 * r)
                new[i] = rcw[i] xor ala(kw) xor
                    tDocB0[byteOf(s[i], 0)] xor tDocB1[byteOf(s[(i + 1) and 3], 1)] xor
                    tDocB2[byteOf(s[(i + 2) and 3], 2)] xor tDocB3[byteOf(s[(i + 3) and 3], 3)]
            }
            s = new
        }
        val k4w = words(keys[4])
        val k4p = intArrayOf(k4w[0], k4w[3], k4w[2], k4w[1]) // pshufd 0x6c
        val v = IntArray(4) { i ->
            tDocfB0[byteOf(s[i], 0)] xor tDocfB1[byteOf(s[(i + 1) and 3], 1)] xor
                tDocfB2[byteOf(s[(i + 2) and 3], 2)] xor tDocfB3[byteOf(s[(i + 3) and 3], 3)] xor
                k4p[i] xor u32le(docC3, 4 * i) xor io[i]
        }
        val gconsts = intArrayOf(0x2965BC00, 0x1664B0A2, 0x84F08D8C.toInt(), 0x52E41983)
        val out = IntArray(4)
        for (i in 0 until 4) {
            val x = ((tDocgB3[byteOf(v[i], 3)].toInt() and 0xff) shl 24) or
                ((tDocgB2[byteOf(v[i], 2)].toInt() and 0xff) shl 16) or
                ((tDocgB1[byteOf(v[i], 1)].toInt() and 0xff) shl 8) or
                (tDocgB0[byteOf(v[i], 0)].toInt() and 0xff)
            val y = x xor gconsts[i]
            out[i] = ((y and 0xFF) shl 24) or ((y and 0xFF00) shl 8) or ((y ushr 8) and 0xFF00) or ((y ushr 24) and 0xFF)
        }
        return out to ioNew
    }

    // ---- encrypt_ingest (0x17fe9b0) / encrypt (0x17fec30) ----------------------------

    private val eiW = mapOf(8 to 0x1DC3032F, 12 to 0x63B3D12E, 0 to 0xA772AB1D.toInt(), 4 to 0xF156A067.toInt())
    private val eiC = mapOf(
        8 to intArrayOf(0x68, 0x3a, 0x54, 0x82), 12 to intArrayOf(0x83, 0x95, 0xed, 0xc2),
        0 to intArrayOf(0xe3, 0x52, 0x56, 0x1d), 4 to intArrayOf(0x35, 0xbd, 0x04, 0x69),
    )
    private val eiT0 = byteTable(0x259ac0) // indexed by b3
    private val eiT1 = byteTable(0x259dc0) // b0
    private val eiT2 = byteTable(0x259cc0) // b1
    private val eiT3 = byteTable(0x259bc0) // b2

    private fun encryptIngest(ctx: ByteArray, block16: ByteArray): IntArray {
        val out = IntArray(4)
        for ((k, o) in listOf(0 to 8, 1 to 12, 2 to 0, 3 to 4)) {
            val x = beWord(block16, o) xor eiW[o]!!
            val c = eiC[o]!!
            // ctx byte-table lookup index may exceed 0xff? No: xor of two bytes stays in range.
            out[k] = ((ctx[0x21f0 + ((eiT0[byteOf(x, 3)].toInt() and 0xff) xor c[3])].toInt() and 0xff) shl 24) or
                (ctx[0x22f0 + ((eiT1[byteOf(x, 0)].toInt() and 0xff) xor c[0])].toInt() and 0xff) or
                ((ctx[0x23f0 + ((eiT2[byteOf(x, 1)].toInt() and 0xff) xor c[1])].toInt() and 0xff) shl 8) or
                ((ctx[0x20f0 + ((eiT3[byteOf(x, 2)].toInt() and 0xff) xor c[2])].toInt() and 0xff) shl 16)
        }
        return out
    }

    private val encC = const16(0x1a41b0)
    private val encRc = listOf(
        0x1a2a10, 0x1a3a30, 0x1a1100, 0x1a0ec0, 0x1a5020,
        0x1a24c0, 0x1a24d0, 0x1a31c0, 0x1a34f0, // last block is "dead" upstream but still XORed in round 0
    ).map { const16(it) }
    private val encC4 = const16(0x1a3a40)
    private val encOutX = intArrayOf(0x50, 0xac, 0x80, 0x82)
    private val encOutStatic = listOf(byteTable(0x2575c0), byteTable(0x2574c0), byteTable(0x2573c0), byteTable(0x2572c0))
    private val encRoundTabs = intArrayOf(0x0f0, 0x4f0, 0x8f0, 0xcf0)
    private val encFinalTabs = intArrayOf(0x18f0, 0x1cf0, 0x10f0, 0x14f0)
    private val encP = intArrayOf(0, 1, 3, 2)

    /** [ctx] is the 0x28F0-byte session context from [initSession]. */
    fun encrypt(ctx: ByteArray, iv16: ByteArray?, data: ByteArray): ByteArray {
        var s: IntArray
        if (iv16 != null) {
            val iw = encryptIngest(ctx, iv16)
            s = IntArray(4) { i -> u32le(encC, 4 * i) xor iw[i] }
        } else {
            s = IntArray(4) { i -> u32le(encC, 4 * i) }
        }
        val o = ByteArray(data.size / 16 * 16)
        for (b in 0 until data.size / 16) {
            val blk = data.copyOfRange(b * 16, b * 16 + 16)
            val t = encryptIngest(ctx, blk)
            var st = intArrayOf(
                s[0] xor t[0] xor u32le(ctx, 8) xor 0x669B24CB,
                s[1] xor t[1] xor u32le(ctx, 0xc) xor 0xF257F9B5.toInt(),
                s[3] xor t[3] xor u32le(ctx, 4) xor 0x0E340D47,
                s[2] xor t[2] xor u32le(ctx, 0) xor 0xC80F1D02.toInt(),
            )
            for (r in 0 until 9) {
                val xw = words(encRc[r])
                val base = (r + 1) * 4
                val kv = intArrayOf(
                    u32le(ctx, 4 * (base + ((r + 3) and 3))),
                    u32le(ctx, 4 * (base + (r and 3))),
                    u32le(ctx, 4 * (base + ((r + 1) and 3))),
                    u32le(ctx, 4 * (base + ((r + 2) and 3))),
                )
                val new = IntArray(4)
                for (i in 0 until 4) {
                    var acc = xw[i] xor kv[i]
                    for (k in 0 until 4) {
                        val srcw = st[encP[(i - k + 4) % 4]]
                        acc = acc xor u32le(ctx, encRoundTabs[k] + 4 * byteOf(srcw, k))
                    }
                    new[i] = acc
                }
                st = intArrayOf(new[0], new[1], new[3], new[2])
            }
            val g = st
            val v = IntArray(4)
            for (i in 0 until 4) {
                var acc = u32le(ctx, 0xa0 + 4 * i) xor u32le(encC4, 4 * i)
                for (k in 0 until 4) {
                    val srcw = g[encP[(i - k + 4) % 4]]
                    acc = acc xor u32le(ctx, encFinalTabs[k] + 4 * byteOf(srcw, k))
                }
                v[i] = acc
            }
            val ob = ByteArray(16)
            for (j in 0 until 4) {
                val w = v[j]
                ob[4 * j + 0] = encOutStatic[0][ctx[0x24f0 + byteOf(w, 3)].toInt() and 0xff xor encOutX[0]]
                ob[4 * j + 1] = encOutStatic[1][ctx[0x25f0 + byteOf(w, 2)].toInt() and 0xff xor encOutX[1]]
                ob[4 * j + 2] = encOutStatic[2][ctx[0x26f0 + byteOf(w, 1)].toInt() and 0xff xor encOutX[2]]
                ob[4 * j + 3] = encOutStatic[3][ctx[0x27f0 + byteOf(w, 0)].toInt() and 0xff xor encOutX[3]]
            }
            ob.copyInto(o, b * 16)
            s = intArrayOf(
                v[2] xor 0x099B2D2C, v[3] xor 0x0F8E4FCD.toInt(),
                v[0] xor 0x58A1D6B2, v[1] xor 0x2EA87554.toInt(),
            )
        }
        return o
    }

    // ---- encsec (0x17fdb50) -----------------------------------------------------------

    private val esT0 = wordTable(0x267ec0)
    private val esT1 = wordTable(0x267ac0)
    private val esT2 = wordTable(0x2676c0)
    private val esT3 = wordTable(0x2672c0)
    private val esF0 = wordTable(0x266ec0)
    private val esF1 = wordTable(0x266ac0)
    private val esF2 = wordTable(0x2666c0)
    private val esF3 = wordTable(0x2662c0)
    private val esSb0 = byteTable(0x25aac0)
    private val esSb1 = byteTable(0x25abc0)
    private val esSb2 = byteTable(0x25adc0)
    private val esSb3 = byteTable(0x25acc0)
    private val esG0 = byteTable(0x25b1c0)
    private val esG1 = byteTable(0x25aec0)
    private val esG2 = byteTable(0x25b0c0)
    private val esG3 = byteTable(0x25afc0)
    private val esRc = listOf(
        0x1a2ee0, 0x1a34c0, 0x1a2ef0, 0x1a2c20, 0x1a4a80,
        0x1a31a0, 0x1a34d0, 0x1a5560, 0x1a4780,
    ).map { const16(it) }
    private val esCfin = const16(0x1a1be0)
    private val esK = intArrayOf(0xb55e5ed8.toInt(), 0x29ed6f36, 0xc6845ce3.toInt(), 0xeb88ed9a.toInt())

    fun encsec(data32: ByteArray): ByteArray {
        var chainC = 0x2DE7A2A5
        var chainD = 0xF081A453.toInt()
        var chainA = 0x18BEC8B9
        var chainB = 0xE88A4A73.toInt()
        val out = ByteArray(32)
        for (blk in 0 until 2) {
            val ib = data32.copyOfRange(blk * 16, blk * 16 + 16)
            val w = IntArray(4)
            for ((k, o) in listOf(0 to 8, 1 to 0xc, 2 to 0, 3 to 4)) {
                val x = beWord(ib, o) xor when (o) {
                    8 -> 0x1A9BD3B4; 0xc -> 0xCFBDBC9D.toInt(); 0 -> 0x3C690967; else -> 0xE8902ED5.toInt()
                }
                w[k] = ((esSb3[byteOf(x, 3)].toInt() and 0xff) shl 24) or
                    ((esSb1[byteOf(x, 1)].toInt() and 0xff) shl 8) or
                    ((esSb2[byteOf(x, 2)].toInt() and 0xff) shl 16) or
                    (esSb0[byteOf(x, 0)].toInt() and 0xff)
            }
            var st = intArrayOf(
                w[0] xor chainA xor 0xDD037774.toInt(),
                w[1] xor chainB xor 0x8279C0E3.toInt(),
                w[2] xor chainC xor 0x4A4BBC3F,
                w[3] xor chainD xor 0xFC774B32.toInt(),
            )
            for (r in 0 until 9) {
                val rcw = words(esRc[r])
                val new = IntArray(4) { i ->
                    esT0[byteOf(st[i], 0)] xor esT1[byteOf(st[(i - 1 + 4) and 3], 1)] xor
                        esT2[byteOf(st[(i - 2 + 4) and 3], 2)] xor
                        esT3[byteOf(st[(i - 3 + 4) and 3], 3)] xor rcw[i]
                }
                st = new
            }
            val t = IntArray(4) { i ->
                esF0[byteOf(st[i], 0)] xor esF1[byteOf(st[(i - 1 + 4) and 3], 1)] xor
                    esF2[byteOf(st[(i - 2 + 4) and 3], 2)] xor
                    esF3[byteOf(st[(i - 3 + 4) and 3], 3)]
            }
            chainA = t[2] xor 0xD0437EA3.toInt()
            chainB = t[3] xor 0xD5E72963.toInt()
            chainC = t[0] xor 0x286B9800
            chainD = t[1] xor 0xD55D8B72.toInt()
            val v = IntArray(4) { i -> t[i] xor u32le(esCfin, 4 * i) }
            for (j in 0 until 4) {
                val x = ((esG0[byteOf(v[j], 3)].toInt() and 0xff) shl 24) or
                    (esG1[byteOf(v[j], 0)].toInt() and 0xff) or
                    ((esG2[byteOf(v[j], 2)].toInt() and 0xff) shl 16) or
                    ((esG3[byteOf(v[j], 1)].toInt() and 0xff) shl 8)
                putU32le(out, blk * 16 + 4 * j, bswap(x xor esK[j]))
            }
        }
        return out
    }

    // ---- spim_map_signature (0x17fe2a0) -------------------------------------------------

    private val smsM = const16(0x1a16e0)
    private val smsC = intArrayOf(0x19B25BBD, 0x9EEA07D0.toInt(), 0x5C67CBDE, 0xD0F30213.toInt())
    private val smsT24 = byteTable(0x25a1c0)
    private val smsT16 = byteTable(0x259fc0)
    private val smsT8 = byteTable(0x259ec0)
    private val smsT0 = byteTable(0x25a0c0)
    private val smsN = const16(0x1a5810)
    private val smsHs = listOf(wordTable(0x264ec0), wordTable(0x264ac0), wordTable(0x2646c0), wordTable(0x2642c0))
    private val smsK = listOf(
        0x1a16f0, 0x1a5b30, 0x1a52a0, 0x1a34e0, 0x1a5570,
        0x1a1f60, 0x1a2c30, 0x1a4790, 0x1a5820,
    ).map { const16(it) }
    private val smsMixt = listOf(wordTable(0x265ec0), wordTable(0x265ac0), wordTable(0x2656c0), wordTable(0x2652c0))
    private val smsCfin2 = const16(0x1a31b0)
    private val smsFt = listOf(byteTable(0x25a2c0), byteTable(0x25a3c0), byteTable(0x25a4c0), byteTable(0x25a5c0))
    private val smsF = intArrayOf(0xE4DF5F73.toInt(), 0x1472A937, 0x6BF137C7, 0x3B7AB732)

    fun spimMapSignature(block16: ByteArray): ByteArray {
        val w0 = words(block16)
        val w = IntArray(4) { j -> bswap(w0[j] xor u32le(smsM, 4 * j)) xor smsC[j] }
        val p = intArrayOf(2, 3, 0, 1)
        var st = IntArray(4) { l ->
            val s = w[p[l]]
            ((smsT24[byteOf(s, 3)].toInt() and 0xff) shl 24) or
                ((smsT16[byteOf(s, 2)].toInt() and 0xff) shl 16) or
                ((smsT8[byteOf(s, 1)].toInt() and 0xff) shl 8) or
                (smsT0[byteOf(s, 0)].toInt() and 0xff) xor u32le(smsN, 4 * l)
        }
        for (r in 0 until 9) {
            val kw = words(smsK[r])
            val new = IntArray(4) { j ->
                smsHs[0][byteOf(st[j], 0)] xor smsHs[1][byteOf(st[(j + 1) and 3], 1)] xor
                    smsHs[2][byteOf(st[(j + 2) and 3], 2)] xor
                    smsHs[3][byteOf(st[(j + 3) and 3], 3)] xor kw[j]
            }
            st = new
        }
        val vv = IntArray(4) { i ->
            var acc = u32le(smsCfin2, 4 * i)
            for (k in 0 until 4) acc = acc xor smsMixt[k][byteOf(st[(i + k) and 3], k)]
            acc
        }
        val out = ByteArray(16)
        for (j in 0 until 4) {
            val wj = vv[j]
            val x = ((smsFt[3][byteOf(wj, 3)].toInt() and 0xff) shl 24) or
                ((smsFt[2][byteOf(wj, 2)].toInt() and 0xff) shl 16) or
                ((smsFt[1][byteOf(wj, 1)].toInt() and 0xff) shl 8) or
                (smsFt[0][byteOf(wj, 0)].toInt() and 0xff)
            putU32le(out, 4 * j, bswap(x xor smsF[j]))
        }
        return out
    }

    // ---- init_session (0x17fcbe0) ---------------------------------------------------------

    // Layout: decodeSpim writes 240 bytes at ctx+0x00; phase 1 consumes dec[0xb0:0xf0]
    // into buf1 (stack); phase 2 expands buf1 into the 8 byte-tables ctx[0x20f0..0x28f0];
    // phase 3 fills the u32 tables ctx[0x0f0..0x20f0] via spim_map. sessionKey = ctx[0:16].

    private val isKa = const16(0x1a4770) + const16(0x1a24b0) + const16(0x1a3780) + const16(0x1a4420)
    private val isKb = const16(0x1a34b0) + const16(0x1a0eb0) + const16(0x1a5800) + const16(0x1a0bd0)
    private val isSbox = listOf(byteTable(0x25a7c0), byteTable(0x25a9c0), byteTable(0x25a8c0), byteTable(0x25a6c0))
    private val isSig = intArrayOf(
        22, 62, 13, 59, 48, 25, 6, 8, 29, 23, 4, 12, 7, 47, 37, 38, 63, 49, 27, 18, 34, 31,
        32, 42, 39, 16, 46, 1, 55, 30, 33, 26, 5, 28, 57, 24, 17, 54, 53, 43, 35, 56, 58, 15,
        3, 51, 0, 19, 36, 60, 21, 11, 50, 40, 45, 20, 41, 44, 2, 9, 10, 14, 52, 61,
    )
    private val isS8 = byteTable(0x2598c0)
    private val isS9 = byteTable(0x2599c0)
    private val isSa = byteTable(0x2596c0)
    private val isSb = byteTable(0x2597c0)

    private fun isPhase1(dec: ByteArray): ByteArray {
        val buf1 = ByteArray(64)
        for (j in 0 until 64) {
            buf1[j] = ((isKb[j].toInt() and 0xff) xor
                (isSbox[j and 3][(dec[0xb0 + j].toInt() and 0xff) xor (isKa[j].toInt() and 0xff)].toInt() and 0xff)).toByte()
        }
        return buf1
    }

    /** fold high-low byte fold (asm: shr bx,8; xor bl). */
    private fun hb(x: Int): Int = (x xor (x ushr 8)) and 0xFF

    private val p3ArgTables = intArrayOf(0x2592c0, 0x258ec0, 0x258ac0, 0x2586c0, 0x2582c0, 0x257ec0, 0x257ac0, 0x2576c0)

    /** (arg xor, out base, idx table offset, idx xor, out xor) per phase-3 write; arg table is p3ArgTables[k]. */
    private val p3Cfg = listOf(
        P3Slot(0xcd, 0x00f0, 0x22f0, 0x21, 0x3483c86d),
        P3Slot(0x26, 0x04f0, 0x23f0, 0x8f, 0x82902656.toInt()),
        P3Slot(0x91, 0x08f0, 0x20f0, 0x52, 0xf2b7a9e0.toInt()),
        P3Slot(0x8a, 0x0cf0, 0x21f0, 0x48, 0x7160fbad),
        P3Slot(0xfa, 0x10f0, 0x20f0, 0x52, 0x45f49eb1),
        P3Slot(0x90, 0x14f0, 0x21f0, 0x48, 0x3bd92f65),
        P3Slot(0xe0, 0x18f0, 0x22f0, 0x21, 0x0fddc438),
        P3Slot(0x96, 0x1cf0, 0x23f0, 0x8f, 0x4df60cb6),
    )

    private class P3Slot(val argXor: Int, val outBase: Int, val idxTab: Int, val idxXor: Int, val outXor: Int)

    private val p3Arg0 = 0xb17f8dc5.toInt() // peeled first-iteration arg (== T2592c0[0xcd])

    /** spim_map (0x17fc600): byte-table gather, OR-combined (bits 24-31 may OR two bytes). */
    private fun spimMap(ctx: ByteArray, x: Int): Int =
        ((ctx[0x23f0 + byteOf(x, 1)].toInt() and 0xff) shl 8) or
            (ctx[0x22f0 + byteOf(x, 0)].toInt() and 0xff) or
            ((ctx[0x20f0 + byteOf(x, 2)].toInt() and 0xff) shl 16) or
            ((ctx[0x21f0 + byteOf(x, 3)].toInt() and 0xff) shl 24)

    fun initSession(spim240: ByteArray): ByteArray {
        val ctx = ByteArray(0x28F0)
        val dec = decodeSpim(spim240)
        dec.copyInto(ctx, 0)

        // phase 1
        val buf1 = isPhase1(dec)

        // phase 2: expand buf1 into the eight ctx byte-tables
        val cw = IntArray(64) { buf1[isSig[it]].toInt() and 0xff }
        val b20f0 = ByteArray(256); val b21f0 = ByteArray(256)
        val b22f0 = ByteArray(256); val b23f0 = ByteArray(256)
        val b24f0 = ByteArray(256); val b25f0 = ByteArray(256)
        val b26f0 = ByteArray(256); val b27f0 = ByteArray(256)
        for (a in 0 until 256) {
            fun foldN(base: Int): Int {
                var f = 0
                for (k in 0 until 8) f = f xor (cw[base + k] * (a and (1 shl k)))
                return f and 0xFFFF
            }
            fun fold1(): Int { // odd word/bit map, only fold1 has it
                var f = 0
                val pairs = listOf(6 to 0, 0 to 1, 1 to 2, 2 to 3, 3 to 4, 4 to 5, 5 to 6, 7 to 7)
                for ((w, b) in pairs) f = f xor (cw[w] * (a and (1 shl b)))
                return f and 0xFFFF
            }
            val f1 = fold1()
            val f2 = foldN(8)
            val f3 = foldN(16)
            val f4 = foldN(24)
            val f5 = foldN(40)
            val f6 = foldN(32)
            val f7 = foldN(48)
            val f8 = foldN(56)
            val s8 = isS8[(hb(f1) xor 0xcb)].toInt() and 0xff
            val s9 = isS9[(hb(f2) xor 0xe9)].toInt() and 0xff
            val sa = isSa[(hb(f3) xor 0x27)].toInt() and 0xff
            val sb = isSb[(hb(f4) xor 0x90)].toInt() and 0xff
            val sc = isS8[(a xor 0xdf)].toInt() and 0xff
            val sd = isS9[(a xor 0xa1)].toInt() and 0xff
            val se = isSa[(a xor 0x14)].toInt() and 0xff
            val sf = isSb[(a xor 0x08)].toInt() and 0xff
            b22f0[a] = (s8 xor 0x1c).toByte()
            b20f0[a] = (sa xor 0xb8).toByte()
            b23f0[a] = (s9 xor 0xf1).toByte()
            b21f0[a] = (sb xor 0x1e).toByte()
            b27f0[(sc xor 0x08) and 0xFF] = hb(f8).toByte()
            b26f0[(sd xor 0x4b) and 0xFF] = hb(f7).toByte()
            b25f0[(se xor 0x43) and 0xFF] = (hb(f6) xor 0x12).toByte()
            b24f0[(sf xor 0x20) and 0xFF] = hb(f5).toByte()
        }
        b20f0.copyInto(ctx, 0x20f0); b21f0.copyInto(ctx, 0x21f0)
        b22f0.copyInto(ctx, 0x22f0); b23f0.copyInto(ctx, 0x23f0)
        b24f0.copyInto(ctx, 0x24f0); b25f0.copyInto(ctx, 0x25f0)
        b26f0.copyInto(ctx, 0x26f0); b27f0.copyInto(ctx, 0x27f0)

        // phase 3: fill the u32 tables ctx[0x0f0..0x20f0] via spim_map
        val idxTabs = mapOf(0x20f0 to b20f0, 0x21f0 to b21f0, 0x22f0 to b22f0, 0x23f0 to b23f0)
        p3Cfg.forEachIndexed { k, slot ->
            val args = wordTable(p3ArgTables[k])
            val idxTab = idxTabs[slot.idxTab]!!
            for (i in 0 until 256) {
                val x = if (i == 0 && k == 0) p3Arg0
                else args[(i xor slot.argXor) and 0xff]
                val v = spimMap(ctx, x) xor slot.outXor
                if (v != 0) {
                    // the binary skips zero stores, so a later 0 must not clobber an earlier value
                    val off = slot.outBase + 4 * ((idxTab[i].toInt() and 0xff) xor slot.idxXor)
                    putU32le(ctx, off, v)
                }
            }
        }
        return ctx
    }

    /** The 16-byte session key is the head of the context (== dec[0:16]). */
    fun sessionKey(ctx: ByteArray): ByteArray = ctx.copyOfRange(0, 16)

    // ---- decryptPTM (0x17ffb50) -----------------------------------------------
    // decryptPTM(key16, data, count, seed16, out): per 16-byte block out_i, the chain
    // advances like docrypt's io; the initial chain is primed from seed16.

    // Initial key-mix head: key words are byte-swapped, xored with per-word constants and
    // run through byte tables; lanes consume D words in order [2,1,0,3].
    private val imC = intArrayOf(0xc92bcef6.toInt(), 0xb3c05bdc.toInt(), 0x7848e9ec, 0xd1e6f246.toInt())
    private val imTa = byteTable(0x25fbc0) // b1, <<8
    private val imTb = byteTable(0x25fdc0) // b2, <<16
    private val imTc = byteTable(0x25fac0) // b3, <<24
    private val imTd = byteTable(0x25fcc0) // b0
    private val imC16 = const16(0x1a5830)

    private fun initMix(key16: ByteArray): IntArray {
        val kw = words(key16)
        val d = IntArray(4) { j -> bswap(kw[j]) xor imC[j] }
        return IntArray(4) { j ->
            val x = d[(2 - j) and 3]
            val v = (imTd[byteOf(x, 0)].toInt() and 0xff) or
                ((imTa[byteOf(x, 1)].toInt() and 0xff) shl 8) or
                ((imTb[byteOf(x, 2)].toInt() and 0xff) shl 16) or
                ((imTc[byteOf(x, 3)].toInt() and 0xff) shl 24)
            v xor u32le(imC16, 4 * j)
        }
    }

    // Phase A: 9 rounds with per-round 16-byte round constants.
    private val paT0 = wordTable(0x260ac0) // b0(S_i)
    private val paT1 = wordTable(0x25fec0) // b1(S_i+1)
    private val paT2 = wordTable(0x2602c0) // b2(S_i+2)
    private val paT3 = wordTable(0x2606c0) // b3(S_i-1)
    private val paRc = listOf(
        0x1a1c00, 0x1a2c40, 0x1a1f80, 0x1a2230, 0x1a13d0, 0x1a2790, 0x1a1110, 0x1a5b50, 0x1a13e0,
    ).map { const16(it) }

    private fun phaseA(s0: IntArray): IntArray {
        var s = s0
        for (r in 0 until 9) {
            val rcw = words(paRc[r])
            s = IntArray(4) { i ->
                paT0[byteOf(s[i], 0)] xor paT1[byteOf(s[(i + 1) and 3], 1)] xor
                    paT2[byteOf(s[(i + 2) and 3], 2)] xor paT3[byteOf(s[(i + 3) and 3], 3)] xor rcw[i]
            }
        }
        return s
    }

    // 4.3: word layer -> byte S-box layers (output-side K1C xor, no consts on layer 2) -> const xor.
    private val f43T0 = wordTable(0x25dac0)
    private val f43T1 = wordTable(0x25dec0)
    private val f43T2 = wordTable(0x25e2c0)
    private val f43T3 = wordTable(0x25e6c0)
    private val f43C1 = const16(0x1a19b0)
    private val f43S1 = listOf(byteTable(0x25d6c0), byteTable(0x25d7c0), byteTable(0x25d8c0), byteTable(0x25d9c0))
    private val f43S2 = listOf(byteTable(0x25d2c0), byteTable(0x25d3c0), byteTable(0x25d4c0), byteTable(0x25d5c0))
    private val f43K1C = byteArrayOf(
        0x66, 0x98.toByte(), 0x1c, 0x7f, 0x7c, 0xb7.toByte(), 0x8f.toByte(), 0x6b,
        0xad.toByte(), 0xe1.toByte(), 0xc0.toByte(), 0x29, 0x00, 0x4f, 0xc3.toByte(), 0x70,
    )
    private val f43C2 = const16(0x1a3e90)

    private fun stage43(dw: IntArray): IntArray {
        val e = IntArray(4) { j ->
            f43T0[byteOf(dw[j], 0)] xor f43T1[byteOf(dw[(j + 1) and 3], 1)] xor
                f43T2[byteOf(dw[(j + 2) and 3], 2)] xor f43T3[byteOf(dw[(j + 3) and 3], 3)] xor
                u32le(f43C1, 4 * j)
        }
        val eb = fromWords(e)
        val l1 = ByteArray(16) { q ->
            (((f43S1[q and 3][eb[q].toInt() and 0xff].toInt() and 0xff) xor f43K1C[q].toInt()) and 0xff).toByte()
        }
        val sb = ByteArray(16) { q -> (f43S2[q and 3][l1[q].toInt() and 0xff].toInt() xor f43C2[q].toInt()).toByte() }
        return words(sb)
    }

    // Key schedule: 10 round words, each derived from the state words and prior keys.
    // 0x1a6aa0 / 0x1a7548 are outside consts.bin -> hardcoded.
    private val ksB = words(const16(0x1a3790)) + words(const16(0x1a3210)) +
        intArrayOf(0x80237707.toInt(), 0x89f00877.toInt())
    private val ksW = words(const16(0x1a47a0)) + words(const16(0x1a52b0)) +
        intArrayOf(0x4d62ea33, 0x03363763)
    private val ksTb0 = wordTable(0x25cac0)
    private val ksTb1 = wordTable(0x25c2c0)
    private val ksTb2 = wordTable(0x25cec0)
    private val ksTb3 = wordTable(0x25c6c0)

    private fun keySchedule(d: IntArray): IntArray {
        val keys = IntArray(10)
        var acc = d[0]
        for (r in 0 until 10) {
            var eax = ksB[r] xor d[1]
            if (r and 1 == 1) eax = eax xor d[2]
            if (((r - 1) and 3) <= 1) eax = eax xor d[3]
            for (k in 1..6) {
                if (r >= k && ((r - k) and 3) <= 1) eax = eax xor keys[k - 1]
            }
            if (r >= 7 && ((r - 7) and 3) != 2) eax = eax xor keys[6]
            if (r >= 8) eax = eax xor keys[7]
            if (r == 9) eax = eax xor keys[8]
            val mix = ksTb0[byteOf(eax, 0)] xor ksTb3[byteOf(eax, 3)] xor ksW[r] xor
                ksTb2[byteOf(eax, 2)] xor ksTb1[byteOf(eax, 1)]
            acc = acc xor mix
            keys[r] = acc
        }
        return keys
    }

    // K0: fold composites over the round words. 0x1a6a10 outside consts.bin -> hardcoded tail.
    private val k0Const = words(const16(0x1a4ce0)) + words(const16(0x1a47b0)) +
        intArrayOf(0x600672ac, 0x77d810cd)
    private val k0F = listOf(
        listOf(1, 2, 3), listOf(2, 3), listOf(3), listOf<Int>(),
        listOf(4), listOf(4, 5), listOf(4, 5, 6), listOf<Int>(), listOf(8), listOf(8, 9),
    )

    private fun deriveK0(keys: IntArray, d: IntArray): IntArray {
        val foldA = keys[0] xor keys[1] xor keys[2] xor keys[3]
        val foldB = foldA xor keys[4] xor keys[5] xor keys[6] xor keys[7]
        return IntArray(10) { i ->
            var x = (if (i >= 7) foldB else foldA) xor d[3] xor k0Const[i]
            for (j in k0F[i]) x = x xor keys[j]
            x
        }
    }

    // K0' is pure constant material (0x1a7120 outside consts.bin -> hardcoded tail).
    private val k0p = words(const16(0x1a13f0)) + words(const16(0x1a1120)) +
        intArrayOf(0xbba29590.toInt(), 0xe3ab739f.toInt())

    // K1: pre_a/pre_b composites + per-block constants; K1[8]/K1[9] extend pre_b with
    // keys[8]/keys[9] and dedicated constants.
    private val k1Ca = const16(0x1a52c0)
    private val k1Cb = const16(0x1a47c0)

    private fun deriveK1(keys: IntArray, d: IntArray): IntArray {
        val k = keys
        val d2 = d[2]
        val d3 = d[3]
        val preA = intArrayOf(k[0] xor d2 xor d3, k[1] xor d2, k[0] xor k[2] xor d2 xor d3, k[1] xor k[3] xor d2)
        val preB = intArrayOf(
            k[0] xor k[2] xor k[4] xor d2 xor d3, k[1] xor k[3] xor k[5] xor d2,
            k[0] xor k[2] xor k[4] xor k[6] xor d2 xor d3, k[1] xor k[3] xor k[5] xor k[7] xor d2,
        )
        val out = IntArray(10)
        for (i in 0 until 4) out[i] = preA[i] xor u32le(k1Ca, 4 * i)
        for (i in 0 until 4) out[4 + i] = preB[i] xor u32le(k1Cb, 4 * i)
        out[8] = (k[0] xor k[2] xor k[4] xor k[6] xor k[8] xor d2 xor d3) xor 0x98564777.toInt()
        out[9] = (k[1] xor k[3] xor k[5] xor k[7] xor k[9] xor d2) xor 0xb1e6e0bc.toInt()
        return out
    }

    // K2: chained fold of the round words over K0'.
    private fun deriveK2(keys: IntArray, d: IntArray): IntArray {
        val dpart = intArrayOf(d[1] xor d[2] xor d[3], d[1] xor d[3], d[1] xor d[2], d[1])
        return IntArray(10) { i ->
            var chain = dpart[i and 3]
            for (kk in 0..i) {
                if (((i - kk) and 3) <= 1) chain = chain xor keys[kk]
            }
            chain xor k0p[i]
        }
    }

    // K3: round words + per-range constants (0x1a7378 outside consts.bin -> hardcoded tail).
    private val k3Ca = const16(0x1a5840)
    private val k3Cb = const16(0x1a2f00)

    private fun deriveK3(keys: IntArray): IntArray = IntArray(10) { i ->
        when {
            i < 4 -> keys[i] xor u32le(k3Ca, 4 * i)
            i < 8 -> keys[i] xor u32le(k3Cb, 4 * (i - 4))
            i == 8 -> keys[8] xor 0x8f438ee4.toInt()
            else -> keys[9] xor 0x1d1474bf
        }
    }

    // K4: outgen of the state words + per-word constant.
    private val k4C = const16(0x1a1c10)

    private fun deriveK4(d: IntArray): IntArray = IntArray(4) { i -> outgen(d[i] xor u32le(k4C, 4 * i)) }

    private fun keyBuf(kd: IntArray): ByteArray = ByteArray(0x30).also { b ->
        for (i in 0 until 10) putU32le(b, 4 * i, kd[i])
    }

    /** decryptPTM (0x17ffb50): docrypt-chain over [data] in 16-byte blocks; [key16] and
     * [seed16] are 16 bytes. Returns count*16 bytes. */
    fun decryptPtm(key16: ByteArray, data: ByteArray, seed16: ByteArray): ByteArray {
        require(key16.size == 16 && seed16.size == 16 && data.size % 16 == 0 && data.isNotEmpty())
        val d = stage43(phaseA(initMix(key16)))
        val keys = keySchedule(d)
        val kbufs = listOf(
            keyBuf(deriveK0(keys, d)), keyBuf(deriveK1(keys, d)),
            keyBuf(deriveK2(keys, d)), keyBuf(deriveK3(keys)), fromWords(deriveK4(d)),
        )
        val t = ingest(seed16)
        var io = intArrayOf(
            t[2] xor u32le(docC1, 8), t[3] xor u32le(docC1, 12),
            t[0] xor u32le(docC1, 0), t[1] xor u32le(docC1, 4),
        )
        val out = ByteArray(data.size)
        for (off in data.indices step 16) {
            val (o, next) = docrypt(data.copyOfRange(off, off + 16), kbufs, io)
            for (i in 0 until 4) putU32le(out, off + 4 * i, o[i])
            io = next
        }
        return out
    }
}
