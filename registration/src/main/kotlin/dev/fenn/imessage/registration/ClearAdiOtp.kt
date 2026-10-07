package dev.fenn.imessage.registration

/**
 * Kotlin transcription of the ClearADI OTP path (OpenBubbles' white-box CoreADI
 * reimplementation, librust_lib_bluebubbles). Address citations refer to that .so.
 * Quirks of the white-box network (dead constants, lane drops, non-standard schedule
 * arithmetic) are reproduced exactly — they are load-bearing, see analysis/otp-path.md.
 */
internal object ClearAdiOtp {

    // ---- helpers -------------------------------------------------------------

    private fun u8(b: ByteArray, i: Int): Int = b[i].toInt() and 0xff

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

    private fun rotr(x: Int, n: Int): Int = (x ushr n) or (x shl (32 - n))
    private fun rotl(x: Int, n: Int): Int = (x shl n) or (x ushr (32 - n))

    /** one byte of a word, position 0 = LSB. */
    private fun byteOf(x: Int, n: Int): Int = (x ushr (8 * n)) and 0xff

    /** XOR of four u32 T-table lookups, one per byte position (tables b0..b3). */
    private fun mix4(x: Int, t0: IntArray, t1: IntArray, t2: IntArray, t3: IntArray): Int =
        t0[byteOf(x, 0)] xor t1[byteOf(x, 1)] xor t2[byteOf(x, 2)] xor t3[byteOf(x, 3)]

    // ---- gentable (0x17f98d0) ------------------------------------------------

    /** gentable: fills ctx[0x130..0x2b0] (384 B) from `one` (client info, 0x190 B). */
    internal fun genTable(ctx: ByteArray, one: ByteArray) {
        val t = ClearAdiTables
        // per-chunk byte-S-box tables (gentable @0x17f99bb-0x17f99d0)
        val sA = t.byteTable(0x2551c0)
        val sB = t.byteTable(0x254ec0)
        val sC = t.byteTable(0x2550c0)
        val sD = t.byteTable(0x254fc0)
        // 9-round Feistel tables (0x17f9bee: slot b0/b3/b1/b2)
        val g0 = t.wordTable(0x254ac0)
        val g3 = t.wordTable(0x253ec0)
        val g1 = t.wordTable(0x2546c0)
        val g2 = t.wordTable(0x2542c0)
        // 10th (final) round tables 0x17f9cd9-0x17f9d49: slot0/3/1/2
        val f0 = t.wordTable(0x2532c0)
        val f3 = t.wordTable(0x253ac0)
        val f1 = t.wordTable(0x2536c0)
        val f2 = t.wordTable(0x252ec0)
        // byte-serial u64 builder tables (0x17f9f05-0x17f9f30)
        val bA = t.byteTable(0x252ac0)
        val bB = t.byteTable(0x252bc0)
        val bC = t.byteTable(0x252cc0)
        val bD = t.byteTable(0x252dc0)
        // 9 round constants, stack order rsp+0x80..0x100 (0x17f9b33-0x17f9bcb)
        val rc = arrayOf(
            0x1a1bc0, 0x1a2200, 0x1a29d0, 0x1a29e0, 0x1a4a70,
            0x1a1f20, 0x1a4190, 0x1a2ec0, 0x1a5af0
        ).map { t.consts16(it) }
        val cFinal = t.consts16(0x1a5d80) // pxor after the 10th round (0x17f9e31)
        val cOut = t.consts16(0x1a3170)   // pxor of each 16-byte output chunk (0x17fa056)
        // 0xC00 qword-index blob copied from .rodata 0x24dcc0 (0x17fa094)
        val blob = ClearAdiTables.blob()

        val buf = ByteArray(0x190)
        // per-chunk 10th-round dword constants: chunk 0 uses the prologue values
        // (17f9971-17f99a8); the loop tail re-derives them from the finished chunk's
        // raw lanes (17f9fe9-17fa02c, 17fa04d-17fa075)
        var cV0 = 0x303d36a2
        var cV1 = 0xeee34595.toInt()
        var cV2 = 0x94edc694.toInt()
        var cV3 = 0x93de8db0.toInt()
        for (chunk in 0 until 25) {
            val o = chunk * 16
            // byte-S-box lanes, 17f99c8-17f9bc7: (bA<<24 ^ bC<<16 ^ bD<<8 ^ bB) per 4 bytes
            val l1 = ((sA[u8(one, o).toInt() xor 0xfc].toInt() and 0xff) shl 24) xor
                ((sC[u8(one, o + 1).toInt() xor 0x30].toInt() and 0xff) shl 16) xor
                ((sD[u8(one, o + 2).toInt() xor 0x19].toInt() and 0xff) shl 8) xor
                (sB[u8(one, o + 3).toInt() xor 0x9f].toInt() and 0xff)
            val l2 = ((sA[u8(one, o + 4).toInt() xor 0xd4].toInt() and 0xff) shl 24) xor
                ((sC[u8(one, o + 5).toInt() xor 0x10].toInt() and 0xff) shl 16) xor
                ((sD[u8(one, o + 6).toInt() xor 0xd].toInt() and 0xff) shl 8) xor
                (sB[u8(one, o + 7).toInt() xor 0x3a].toInt() and 0xff)
            val l3 = ((sA[u8(one, o + 8).toInt() xor 0x48].toInt() and 0xff) shl 24) xor
                ((sC[u8(one, o + 9).toInt() xor 0x30].toInt() and 0xff) shl 16) xor
                ((sD[u8(one, o + 10).toInt() xor 0x89].toInt() and 0xff) shl 8) xor
                (sB[u8(one, o + 11).toInt() xor 0x6b].toInt() and 0xff)
            val l4 = ((sA[u8(one, o + 12).toInt() xor 0x12].toInt() and 0xff) shl 24) xor
                ((sC[u8(one, o + 13).toInt() xor 0xc5].toInt() and 0xff) shl 16) xor
                ((sD[u8(one, o + 14).toInt() xor 0x6d].toInt() and 0xff) shl 8) xor
                (sB[u8(one, o + 15).toInt() xor 0x89].toInt() and 0xff)
            // The .so's round-1 setup loads eax=d, ebx=a, edi=b, r9d=c (17f9b41-17f9bb7)
            // while the loop-back extraction (17f9bd0-17f9bea) keeps the plain state —
            // so round 1's Feistel input is the state rotated by one lane.
            var a = l4 xor 0x5fdff073.toInt() // 17f9bbe
            var b = l1 xor 0x948c2d71.toInt() // 17f9b1a
            var c = l2 xor 0x5f1a4c6e.toInt() // 17f9b67
            var d = l3 xor 0xb026a63d.toInt() // 17f9bb7
            // 9 uniform Feistel rounds + per-round 16-byte constant (17f9bee-17f9cd3)
            for (r in 0 until 9) {
                val n0 = g0[byteOf(a, 0)] xor g3[byteOf(d, 3)] xor g1[byteOf(b, 1)] xor g2[byteOf(c, 2)]
                val n1 = g0[byteOf(b, 0)] xor g3[byteOf(a, 3)] xor g1[byteOf(c, 1)] xor g2[byteOf(d, 2)]
                val n2 = g0[byteOf(c, 0)] xor g3[byteOf(b, 3)] xor g1[byteOf(d, 1)] xor g2[byteOf(a, 2)]
                val n3 = g0[byteOf(d, 0)] xor g3[byteOf(c, 3)] xor g1[byteOf(a, 1)] xor g2[byteOf(b, 2)]
                val k = rc[r]
                a = n0 xor u32le(k, 0)
                b = n1 xor u32le(k, 4)
                c = n2 xor u32le(k, 8)
                d = n3 xor u32le(k, 12)
            }
            // 10th round, uniform lane rotation (17f9cd9-17f9e31): output i combines
            // f0[s_i,0] ^ f1[s_{i+1},1] ^ f3[s_{i+2},2] ^ f2[s_{i+3},3] ^ dword-constant
            val v0 = f0[byteOf(a, 0)] xor f1[byteOf(b, 1)] xor f2[byteOf(c, 2)] xor
                f3[byteOf(d, 3)] xor cV0
            val v1 = f0[byteOf(b, 0)] xor f1[byteOf(c, 1)] xor f2[byteOf(d, 2)] xor
                f3[byteOf(a, 3)] xor cV1
            val v2 = f0[byteOf(c, 0)] xor f1[byteOf(d, 1)] xor f2[byteOf(a, 2)] xor
                f3[byteOf(b, 3)] xor cV2
            val v3 = f0[byteOf(d, 0)] xor f1[byteOf(a, 1)] xor f2[byteOf(b, 2)] xor
                f3[byteOf(c, 3)] xor cV3
            val k = cFinal
            val u0 = v0 xor u32le(k, 0)
            val u1 = v1 xor u32le(k, 4)
            val u2 = v2 xor u32le(k, 8)
            val u3 = v3 xor u32le(k, 12)
                // byte-serial u64s, chain order (u0,u3) then (u2,u1) (17f9f0c-17fa041)
            val c1 = intArrayOf(
                bA[byteOf(u0, 0)].toInt(), bB[byteOf(u0, 1)].toInt(), bC[byteOf(u0, 2)].toInt(), bD[byteOf(u0, 3)].toInt(),
                bA[byteOf(u3, 0)].toInt(), bB[byteOf(u3, 1)].toInt(), bC[byteOf(u3, 2)].toInt(), bD[byteOf(u3, 3)].toInt()
            )
            val c2 = intArrayOf(
                bA[byteOf(u2, 0)].toInt(), bB[byteOf(u2, 1)].toInt(), bC[byteOf(u2, 2)].toInt(), bD[byteOf(u2, 3)].toInt(),
                bA[byteOf(u1, 0)].toInt(), bB[byteOf(u1, 1)].toInt(), bC[byteOf(u1, 2)].toInt(), bD[byteOf(u1, 3)].toInt()
            )
            // stored as two little-endian u64s (movq at 17fa046/17fa05b) then ^ cOut
            for (i in 0 until 8) {
                buf[o + i] = (c1[7 - i] xor u8(cOut, i)).toByte()
                buf[o + 8 + i] = (c2[7 - i] xor u8(cOut, 8 + i)).toByte()
            }
            // carry: next chunk's constants from this chunk's raw lanes
            // (17f9fe9-17fa00a: l3^0x8af594de -> out2 slot; 17fa015/25: l1^0x60a97028 ->
            // out4 slot; 17fa01a/2c: l4^0x19bfc026 -> out3 slot; 17fa04d/05f:
            // l2^0x8baea5ec -> out1 slot)
            cV0 = l2 xor 0x8baea5ec.toInt()
            cV1 = l3 xor 0x8af594de.toInt()
            cV2 = l4 xor 0x19bfc026
            cV3 = l1 xor 0x60a97028
        }
        // byte-mixing loop over the blob + buf (17fa08a-17fa134)
        var acc = (u8(buf, 0x122) + u8(buf, 0x13f) + u8(buf, 0x0e) + u8(buf, 0x124)) and 0xff
        for (i in 0 until 0x180) {
            val idx = u32le(blob, 8 * i) // blob qwords are small indices
            val v = u8(buf, idx)
            val m = acc and 7
            if ((acc and 6) == 2) {
                // m in {2,3}: ctx = (acc ^ v) & 0xff, acc' = v + 0x12 (17fa109-17fa122)
                ctx[0x130 + i] = ((acc xor v) and 0xff).toByte()
                acc = v + 0x12
            } else {
                // m in {0,1,4..7}: ctx = bb & 0xff, acc' = (acc ^ bb) + 0x12
                // (17fa0c0-17fa0d9; `add bl,buf[idx]` wraps within byte 0)
                val bb = when (m) {
                    0 -> v - acc
                    1 -> (acc and 0xffffff00.toInt()) or ((acc + v) and 0xff)
                    else -> v
                }
                ctx[0x130 + i] = (bb and 0xff).toByte()
                acc = (acc xor bb) + 0x12
            }
        }
    }

    // ---- schedule expansion shared by the gensource hash stages (SIMD-recovered) --

    /**
     * The white-box SHA-256-flavored message schedule: for i in 16..63,
     * W[i] = W[i-16] + (rotr(W[i-2],19)^rotr(W[i-2],17)) ^ (W[i-7] ^ (W[i-2]>>>10))
     *                   ^ ((rotr(W[i-15],7)^rotr(W[i-15],18)) - (W[i-15]>>>3))
     * (sigma1 lacks its >>>10 term — it is XORed into the W[i-7] slot instead; sigma0's
     * >>>3 term is subtracted, not XORed — 0x17fa449/0x17fa4dd.)
     */
    private fun expandSchedule(w: IntArray) {
        for (i in 16 until 64) {
            val c = w[i - 2]
            val s1 = rotr(c, 19) xor rotr(c, 17)
            val t = w[i - 7] xor (c ushr 10)
            val v = w[i - 15]
            val s0 = (rotr(v, 7) xor rotr(v, 18)) - (v ushr 3)
            w[i] = w[i - 16] + (s1 xor t xor s0)
        }
    }

    // ---- the 64-round ARX permutation of gensource (0x17fa54c, 0x17fad5d, 0x17fb8d1) --

    internal class ArxResult(
        val out1: Int,
        val out2: Int,
        val s1: Int,
        val s2: Int,
        val s3: Int,
        val s4: Int,
        val s5: Int,
        val s6: Int,
    )

    /** Initial ARX state [s0..s6, d] — the constants at 17fad31-17fad58. */
    private val ARX_STD_INIT = intArrayOf(
        0x16a4e72b, 0x42b9ab8c.toInt(), 0x95a2bd45.toInt(), 0xcc9f011e.toInt(),
        0x460b9fe5.toInt(), 0x0364e21c, 0x5e7aa279, 0x499b3b76,
    )

    private fun arx(w: IntArray, mixTable: IntArray, init: IntArray = ARX_STD_INIT): ArxResult {
        var s0 = init[0]
        var s1 = init[1]
        var s2 = init[2]
        var s3 = init[3]
        var s4 = init[4]
        var s5 = init[5]
        var s6 = init[6]
        var d = init[7]
        var out1 = 0
        var out2 = 0
        for (i in 0 until 64) {
            // 17fa55f-17fa5d3
            val x = s3
            val t = rotr(x, 13) xor rotr(x, 2) xor rotl(x, 10)
            val m2 = (((((s2 xor s1) and s3) xor s2) - s1)) * 2
            val o1 = m2 xor t
            val e = rotl(s6, 7) + rotr(s6, 6) - rotr(s6, 11)
            val o2 = (w[i] - s6) + 2 * s4 + 0x6f5d3d27 - mixTable[i] + (s6 xor s5) - (d xor e)
            out1 = o1 + o2
            out2 = o2 + s0
            if (i == 63) break
            val ns0 = s1; val ns1 = s2; val ns2 = s3; val ns3 = out1
            val ns4 = s5; val ns5 = s6; val ns6 = out2; val nd = s4
            s0 = ns0; s1 = ns1; s2 = ns2; s3 = ns3; s4 = ns4; s5 = ns5; s6 = ns6; d = nd
        }
        return ArxResult(out1, out2, s1, s2, s3, s4, s5, s6)
    }

    // ---- gensource (0x17fa240) -------------------------------------------------

    /** 8 shift-amount bytes at .rodata 0x1a7948 (read through rsp+0x58). */
    private val SHIFT_BYTES = byteArrayOf(0x10, 0x00, 0x08, 0x18, 0x10, 0x10, 0x08, 0x08)

    /** gensource: fills ctx[0x2c0..0x320] (24 round-constant dwords) from `two` and `gen`. */
    internal fun genSource(ctx: ByteArray, two: ByteArray, gen: UInt) {
        val t = ClearAdiTables
        val c44 = t.consts16(0x1a3180)
        val c4730 = t.consts16(0x1a4730)
        val c1f30 = t.consts16(0x1a1f30)
        val mt = t.wordTable(0x24e8c0, 64)

        // ---- stage 1: buffer A from `two`, hash expansion, ARX (17fa2d3-17fa5dd) ----
        val src = ByteArray(64)
        for (i in 0 until 32) src[i] = (two[i].toInt() xor c44[i and 15].toInt()).toByte()
        c4730.copyInto(src, 32)
        c1f30.copyInto(src, 48)
        val a = IntArray(64)
        for (j in 0 until 16) a[j] = Integer.reverseBytes(u32le(src, 4 * j)) xor 0x77777777
        expandSchedule(a)
        val r1 = arx(a, mt)

        // ctx[0x2c0..0x2e0] (17fa5e3-17fa6ac)
        val p = 0xcc9f011e.toInt() - r1.out1
        val q = r1.s3
        val r = 0x42b9ab8c.toInt() - r1.s2
        val s = r1.s1
        val tv = 0xa1855d85.toInt() - r1.out2
        val u = r1.s6
        val v = 0x460b9fe5.toInt() - r1.s5
        val w = 0x499b3b76 - r1.s4
        putCtxXor(ctx, 0x2c0, intArrayOf(p, q, r, s), 0x1a1bd0)
        putCtxXor(ctx, 0x2d0, intArrayOf(tv, u, v, w), 0x1a2ed0)

        // ---- 15 constant blocks + 8-byte tail over rsp+0x168..0x260 (17fa5e3-17fa955)
        val c43f0 = t.consts16(0x1a43f0)
        val c0980 = t.consts16(0x1a0980)
        val c5b00 = t.consts16(0x1a5b00)
        val c0bb0 = t.consts16(0x1a0bb0)
        val c2ed0 = t.consts16(0x1a2ed0)
        val c3e40 = t.consts16(0x1a3e40)
        val c1f40 = t.consts16(0x1a1f40)
        val c3c40 = t.consts16(0x1a3c40)
        val c2480 = t.consts16(0x1a2480)
        val c3750 = t.consts16(0x1a3750)
        val c13b0 = t.consts16(0x1a13b0)
        val c3e50 = t.consts16(0x1a3e50)
        val c13c0 = t.consts16(0x1a13c0)
        val c2740 = t.consts16(0x1a2740)
        val c0bc0 = t.consts16(0x1a0bc0)
        // dword index space D[] starts at rsp+0x160; D[0..1] unwritten, D[2..] = blocks
        val dReg = IntArray(64)
        putXor4(dReg, 2, intArrayOf(s, s, w, tv), c43f0)      // rsp+0x168
        putXor4(dReg, 6, intArrayOf(u, u, v, v), c0980)      // rsp+0x178
        putXor4(dReg, 10, intArrayOf(q, p, w, q), c5b00)     // rsp+0x188
        putXor4(dReg, 14, intArrayOf(w, r, r, s), c0bb0)     // rsp+0x198
        putXor4(dReg, 18, intArrayOf(w, u, w, v), c2ed0)     // rsp+0x1a8
        putXor4(dReg, 22, intArrayOf(q, w, v, p), c3e40)     // rsp+0x1b8
        putXor4(dReg, 26, intArrayOf(u, r, w, s), c1f40)     // rsp+0x1c8
        putXor4(dReg, 30, intArrayOf(s, tv, r, u), c3c40)    // rsp+0x1d8
        putXor4(dReg, 34, intArrayOf(s, w, w, p), c2480)     // rsp+0x1e8
        putXor4(dReg, 38, intArrayOf(u, q, v, r), c3750)     // rsp+0x1f8
        putXor4(dReg, 42, intArrayOf(q, tv, w, u), c13b0)    // rsp+0x208
        putXor4(dReg, 46, intArrayOf(w, v, r, w), c3e50)     // rsp+0x218
        putXor4(dReg, 50, intArrayOf(w, q, w, r), c13c0)     // rsp+0x228
        putXor4(dReg, 54, intArrayOf(q, s, v, tv), c2740)    // rsp+0x238
        putXor4(dReg, 58, intArrayOf(u, v, w, w), c0bc0)     // rsp+0x248
        dReg[62] = s xor 0x22585f05                          // rsp+0x258 (17fa8f8/17fa815)
        dReg[63] = p xor 0x34fcb82e.toInt()                  // rsp+0x25c (17fa906/17fa8f2)

        // ---- buf32 (rsp+0x560..0x580), 17fa94e-17faac8 ----
        val buf32 = ByteArray(32)
        // buf32[0] (17fa894-17fa966)
        buf32[0] = ((((r ushr 16) + 0x2a) xor (q xor u32le(c5b00, 0))) xor 0x59).toByte()
        // buf32[1] (17fa748-17fa973); rsp+0x16f = byte 7 of block168
        val sC0 = s xor u32le(c43f0, 0)
        val sC1 = s xor u32le(c43f0, 4)
        buf32[1] = ((((sC0 xor 0x34fcb82e.toInt()) ushr 8) + 0x2a) xor (sC1 ushr 24) xor 0x43).toByte()
        for (j in 2 until 32) {
            val sh = 2 * (j and 3)
            val hi = dReg[2 * j] xor 0x34fcb82e.toInt()
            val lo = dReg[2 * j + 1] xor 0x34fcb82e.toInt()
            buf32[j] = (((hi ushr (SHIFT_BYTES[sh].toInt() and 31)) + 0x2a) xor
                (lo ushr (SHIFT_BYTES[sh + 1].toInt() and 31)) xor 0x77).toByte()
        }

        // ---- stage 2: buffer B = buf32 duplicated (64 B), hash, ARX (17faace-17faded) ----
        val bufB = ByteArray(64)
        buf32.copyInto(bufB, 0)
        buf32.copyInto(bufB, 32)
        val b = IntArray(64)
        for (j in 0 until 16) b[j] = Integer.reverseBytes(u32le(bufB, 4 * j)) xor 0x77777777
        expandSchedule(b)
        val r2 = arx(b, mt)
        // scalar slots saved for the gen section: n1/n2c/n2 XOR partners
        // (17faed9-17faeee store [rsp+0x30/0x34/0x38] from xmm15/xmm12 = stage-1
        // state lanes ^ C1a1bd0 / C1a2ed0, kept live from 17fa614/17fa672)
        val c1a1bd0 = t.consts16(0x1a1bd0)
        val c1a2ed0 = t.consts16(0x1a2ed0)
        val slot30 = r2.s3 xor u32le(c1a1bd0, 4)  // xmm15[1] = s3 ^ C1a1bd0[1]
        val slot34 = r2.s1 xor u32le(c1a1bd0, 12) // xmm15[3] = s1 ^ C1a1bd0[3]
        val slot38 = r2.s6 xor u32le(c1a2ed0, 4)  // xmm12[1] = s6 ^ C1a2ed0[1]
        val s42 = r2.s4
        val s52 = r2.s5

        // ---- stage 3: ARX over the padding-block schedule (17faecb-17fb22f) ----
        // buffer C at rsp+0x360: word0 = C1a3c50[0..3] raw; words 1..15 = C1a3c50[4..],
        // C1a4740, C1a4740, C1a5d90 through the bswap^0x77777777 loop (17faf10-17fafa7);
        // words 16..63 expanded (17fafc0-17fb127). Its init state comes from the stage-2
        // lanes packed at 17fae37-17fae93, ^ C4cc0/C34a0 (17fb12d/17fb136) — verified
        // against live registers (ebp/r11d/ebx/r8d/r12d/r13d/edi/edx at 17fb1b1).
        val c1a3c50 = t.consts16(0x1a3c50)
        val c1a4740 = t.consts16(0x1a4740)
        val c1a5d90 = t.consts16(0x1a5d90)
        val cbuf = ByteArray(0x100)
        c1a3c50.copyInto(cbuf, 0)
        c1a4740.copyInto(cbuf, 0x10)
        c1a4740.copyInto(cbuf, 0x20)
        c1a5d90.copyInto(cbuf, 0x30)
        val c = IntArray(64)
        c[0] = u32le(cbuf, 0) // byte 0x360-0x364 sits before the bswap loop's reach
        for (j in 1 until 16) c[j] = Integer.reverseBytes(u32le(cbuf, 4 * j)) xor 0x77777777
        expandSchedule(c)
        val c4cc0 = t.consts16(0x1a4cc0)
        val c34a0 = t.consts16(0x1a34a0)
        val st3Init = intArrayOf(
            r2.s1 xor u32le(c4cc0, 12),                          // s0 = ebp
            (0x42b9ab8c.toInt() - r2.s2) xor u32le(c4cc0, 8),    // s1 = r11d
            r2.s3 xor u32le(c4cc0, 4),                           // s2 = ebx
            (0xcc9f011e.toInt() - r2.out1) xor u32le(c4cc0, 0),  // s3 = r8d
            (0x460b9fe5.toInt() - r2.s5) xor u32le(c34a0, 8),    // s4 = r12d
            r2.s6 xor u32le(c34a0, 4),                           // s5 = r13d
            (0xa1855d85.toInt() - r2.out2) xor u32le(c34a0, 0),  // s6 = edi
            (0x499b3b76 - r2.s4) xor u32le(c34a0, 12),           // d  = edx
        )
        val r4 = arx(c, mt, st3Init)

        // ---- gen section (17fb235-17fb666) ----
        val g = gen.toInt()
        val n1 = (r4.s3 xor slot30).inv()
        val n2c = (r4.s1 xor slot34).inv()
        val n2 = (r4.s6 xor slot38).inv()
        val rq = ((r2.s2 - 0x42b9ab8d) - r4.s2) xor 0x34fcb82e.toInt()
        val gq = ((s52 - 0x460b9fe6) - r4.s5) xor 0x34fcb82e.toInt()
        val hq = ((s42 - 0x499b3b77) - r4.s4) xor 0x34fcb82e.toInt()
        val e1 = ((r2.out1 + 0x3360fee1) - r4.out1) xor 0x34fcb82e.toInt()
        // 17fb28f-17fb2cc: 0xa1855d84 - r2.out2 - r4.out2, ^ 0x34fcb82e
        val e2v = ((0xa1855d84.toInt() - r2.out2) - r4.out2) xor 0x34fcb82e.toInt()
        putCtxXor(ctx, 0x2e0, intArrayOf(e1, n1, rq, n2c), null)
        putCtxXor(ctx, 0x2f0, intArrayOf(e2v, n2, gq, hq), null)

        // gen math + shuffle-region seed bytes (17fb2aa-17fb483)
        val h1v = (g.toLong() * 0x12e0a56bL) ushr 32
        val t1 = ((g - h1v.toInt()).toLong() and 0xffffffffL)
        val r14v = (t1 ushr 1) + h1v
        val r14w2 = ((r14v ushr 29) and 0xffff).toInt()
        val h3v = (g.toLong() * 0x1b39aeb3L) ushr 60
        val dx16 = (h3v and 0xffff).toInt()
        val h4v = (g.toLong() * 0x7b85ee89L) ushr 57
        val cx16 = (h4v and 0xffff).toInt()
        val r13w = ((g.toLong() * 0x9c715473L) ushr 61 and 0xffff).toInt()

        var ebpV = (r4.s1 and 0xffff0000.toInt()) or ((r14w2 * 0x308f) and 0xffff)
        ebpV += g
        ebpV = (ebpV and 0xffff0000.toInt()) or ((ebpV and 0xffff) xor 0x7777)
        val ebpB0 = ebpV and 0xff
        val ebpB1 = (ebpV ushr 8) and 0xff

        var esiV = (e1 and 0xffff0000.toInt()) or ((cx16 * 0xe329) and 0xffff)
        esiV += g
        esiV = (esiV and 0xffff0000.toInt()) or ((esiV and 0xffff) xor 0x7777)
        val rdxByte = esiV and 0xff
        val rcxByte = (esiV ushr 8) and 0xff

        // r15 seed: (hq high ‖ dx16*0x4467) + g, low word ^ 0x7777 (17fb321/17fb364/17fb378)
        var r15dV = (hq and 0xffff0000.toInt()) or ((dx16 * 0x4467) and 0xffff)
        r15dV += g
        r15dV = (r15dV and 0xffff0000.toInt()) or ((r15dV and 0xffff) xor 0x7777)
        val r15Byte = r15dV and 0xff
        val rsiByte = (r15dV ushr 8) and 0xff

        val mVal = (r13w * 0xc259) and 0xffff
        var r11dV = (e2v and 0xffff0000.toInt()) or mVal
        r11dV += g // 17fb412: ebx was reloaded with g at 17fb2e1 (mov rbx,r13)
        r11dV = (r11dV and 0xffff0000.toInt()) or ((r11dV and 0xffff) xor 0x7777)
        val r14Byte = ((r11dV and 0xffff) ushr 8) and 0xff
        val two1 = u8(two, 1)
        val ebx32 = (((two1 xor 0x33) - 0x6d) xor r11dV)
        val eaxByte = ebx32 and 0xff
        val chain0 = (((ebx32 xor 0x77) * 0x44) xor 0xffffff98.toInt())

        // 64-byte shuffle region rsp+0x580..0x5c0 (17fb47b-17fb5c0 + blocks)
        val shuf = ByteArray(64)
        // rax qword (17fb433-17fb47b): rax = eaxByte, then 7× (shl 8 | reg) — the last
        // or'ed reg lands in byte 0, so memory order = [r9, rbp, rsi, r15, rcx, rdx, r14, eax]
        shuf[0] = ebpB1.toByte(); shuf[1] = ebpB0.toByte()
        shuf[2] = rsiByte.toByte(); shuf[3] = r15Byte.toByte()
        shuf[4] = rcxByte.toByte(); shuf[5] = rdxByte.toByte()
        shuf[6] = r14Byte.toByte(); shuf[7] = eaxByte.toByte()
        val c4740 = t.consts16(0x1a4740)
        c4740.copyInto(shuf, 8)
        c4740.copyInto(shuf, 24)
        c4740.copyInto(shuf, 40)
        shuf[55] = 0xf7.toByte() // 17fb3b3
        for (i in 56 until 62) shuf[i] = 0x77.toByte() // 17fb245-17fb25c
        shuf[62] = 0x76; shuf[63] = 0xcf.toByte() // word 0xcf76 LE (17fb358/17fb389)
        // byte shuffle loop, 19 iterations of 5 (17fb490-17fb660; cmp r13d,0x67 ends at n=103);
        // pos = n - 55*q(n)
        var chain = chain0
        for (k in 0 until 19) {
            val base = 8 + 5 * k
            val ti = 3 + 10 * k
            for (mm in 0 until 5) {
                val n = base + mm
                val qn = ((n.toLong() * 156180629L) ushr 33).toInt() // magic 0x94f2095, >>33
                val pos = n - 55 * qn
                val twoByte = u8(two, (ti + 2 * mm) and 0x1f)
                val v = (twoByte xor 0x33) + (chain xor 0xb)
                val newByte = (v and 0xff) xor u8(shuf, pos)
                shuf[pos] = newByte.toByte()
                // chain update uses v with its low byte already replaced by the new
                // shuf byte (asm xor sil,[shuf] happens before xor esi,0x77)
                chain = chain xor ((((v and 0xffffff00.toInt()) or newByte) xor 0x77) * 0x44)
            }
        }

        // ---- stage 4: buffer D = shuffled64, hash, ARX (17fb666-17fb99a) ----
        val dd = IntArray(64)
        for (j in 0 until 16) dd[j] = Integer.reverseBytes(u32le(shuf, 4 * j)) xor 0x77777777
        expandSchedule(dd)
        val r3 = arx(dd, mt)
        putCtxXor(ctx, 0x300, intArrayOf(
            0xcc9f011e.toInt() - r3.out1, r3.s3, 0x42b9ab8c.toInt() - r3.s2, r3.s1), 0x1a1bd0)
        putCtxXor(ctx, 0x310, intArrayOf(
            0xa1855d85.toInt() - r3.out2, r3.s6, 0x460b9fe5.toInt() - r3.s5, 0x499b3b76 - r3.s4), 0x1a2ed0)
    }

    private fun putCtxXor(ctx: ByteArray, off: Int, values: IntArray, constVaddr: Int?) {
        val c = constVaddr?.let { ClearAdiTables.consts16(it) }
        for (i in 0 until 4) {
            val x = if (c != null) values[i] xor u32le(c, 4 * i) else values[i]
            putU32le(ctx, off + 4 * i, x)
        }
    }

    private fun putXor4(target: IntArray, at: Int, values: IntArray, const16: ByteArray) {
        for (i in 0 until 4) target[at + i] = values[i] xor u32le(const16, 4 * i)
    }    // ---- gen_otp (0x17fba60) ---------------------------------------------------

    /** gen_otp: IOS-flavor ADI cipher; 16-byte output. `one` = 0x190 client-info bytes. */
    internal fun genOtp(gen: UInt, one: ByteArray, two: ByteArray): ByteArray {
        val t = ClearAdiTables
        val ctx = ByteArray(0x320)
        genSource(ctx, two, gen)
        genTable(ctx, one)

        // A: ctx[0x70+4m] = bswap(ctx[0x210+4m] ^ ctx[0x160+4m]) (17fbac4-17fbb7b)
        for (m in 0 until 40) {
            putU32le(ctx, 0x70 + 4 * m,
                Integer.reverseBytes(u32le(ctx, 0x210 + 4 * m) xor u32le(ctx, 0x160 + 4 * m)))
        }

        // B: h[i] = bswap(ctx[0x130+4i]); ctx[0x120..0x130] = [h4..h7] (17fbb81-17fbc89)
        val h = IntArray(8) { Integer.reverseBytes(u32le(ctx, 0x130 + 4 * it)) }
        for (i in 0 until 4) putU32le(ctx, 0x120 + 4 * i, h[4 + i])
        // (ctx[0x110..0x120] = [h3,h1,h2,h0] is written by the binary but never read)

        // C: key schedule (17fbd39-17fbd6e)
        val hi0 = t.wordTable(0x251ac0); val hi1 = t.wordTable(0x251ec0)
        val hi2 = t.wordTable(0x2522c0); val hi3 = t.wordTable(0x2526c0)
        val lo0 = t.wordTable(0x250ac0); val lo1 = t.wordTable(0x250ec0)
        val lo2 = t.wordTable(0x2512c0); val lo3 = t.wordTable(0x2516c0)
        val rcA = t.consts16(0x1a41a0)   // RC[0..3]
        val rcB = t.consts16(0x1a2750)   // RC[4..23] (repeated)
        for (i in 0 until 24) {
            var x = u32le(ctx, 0x2c0 + 4 * i)
            if (i < 4) x = x xor u32le(ctx, 0x120 + 4 * i)
            val hiMix = hi0[byteOf(x, 3)] xor hi1[byteOf(x, 0)] xor
                hi2[byteOf(x, 2)] xor hi3[byteOf(x, 1)]
            val loMix = lo0[byteOf(hiMix, 0)] xor lo1[byteOf(hiMix, 1)] xor
                lo2[byteOf(hiMix, 2)] xor lo3[byteOf(hiMix, 3)]
            var k = loMix xor (if (i < 4) u32le(rcA, 4 * i) else u32le(rcB, 4 * (i and 3)))
            if (i < 4) k = k xor u32le(ctx, 0x70 + 4 * i) xor 0xd247337c.toInt()
            putU32le(ctx, 0x10 + 4 * i, k)
        }

        // tail blocks: iteration t uses ctx[0x80+0x10t..] ^ C (pshufd-reversed) (17fbd70-17fbeef)
        val tailConst = intArrayOf(
            0x1a4cd0, 0x1a2770, 0x1a3190, 0x1a1f50, 0x1a2490,
            0x1a2210, 0x1a3e60, 0x1a29f0, 0x1a2760
        )
        val tail = Array(9) { tt ->
            val src = IntArray(4) { u32le(ctx, 0x80 + 0x10 * tt + 4 * it) }
            val c = t.consts16(tailConst[tt])
            // pshufd 0x1b reverses dwords; usage: n0^dst[3], n1^dst[2], n2^dst[1], n3^dst[0]
            intArrayOf(src[0] xor u32le(c, 12), src[1] xor u32le(c, 8),
                src[2] xor u32le(c, 4), src[3] xor u32le(c, 0))
        }

        // sieve chunks: iteration t reads the 16 bytes at consts below (17fbe85-17fbf27;
        // stack order rsp+0xf0.. — note 0x1a24a0 (xmm3) lands BEFORE 0x1a3760 (xmm4))
        val sieveConst = intArrayOf(
            0x1a3e70, 0x1a24a0, 0x1a3760, 0x1a3a20, 0x1a4400,
            0x1a1990, 0x1a16d0, 0x1a5010, 0x1a0990
        )
        val sieve = Array(9) { t.consts16(sieveConst[it]) }

        val tF5 = t.wordTable(0x24f5c0)
        val tF1 = t.wordTable(0x24f1c0)
        val tED = t.wordTable(0x24edc0)
        val tE9 = t.wordTable(0x24e9c0)

        // stage-2 S-box tables (0x24fac0/0x24fec0/0x2502c0/0x2506c0, b3/b0/b1/b2) and the
        // w-block dword outputs, computed inside every round (17fc0d9-17fc311)
        val tFa = t.wordTable(0x24fac0)
        val tFe = t.wordTable(0x24fec0)
        val t02 = t.wordTable(0x2502c0)
        val t06 = t.wordTable(0x2506c0)
        fun stage2(x: Int): Int = tFa[byteOf(x, 3)] xor tFe[byteOf(x, 0)] xor
            t02[byteOf(x, 1)] xor t06[byteOf(x, 2)]
        var dwordA = 0; var dwordB = 0; var dwordC = 0; var dwordD = 0

        var s0 = 0x25e22f28
        var s1 = 0x58cff744
        var s2 = 0x36ac60aa
        var s3 = 0x2906000b
        var n0 = 0; var n1 = 0; var n2 = 0; var n3 = 0
        for (round in 0 until 6) {
            // key dwords K[4r..4r+3] (17fbf4f-17fbf62)
            s0 = s0 xor u32le(ctx, 0x10 + 0x10 * round)
            s3 = s3 xor u32le(ctx, 0x14 + 0x10 * round)
            s1 = s1 xor u32le(ctx, 0x18 + 0x10 * round)
            s2 = s2 xor u32le(ctx, 0x1c + 0x10 * round)
            for (tt in 0 until 9) {
                val sv = sieve[tt]
                val tl = tail[tt]
                n0 = tF5[byteOf(s3, 2) xor u8(sv, 0)] xor tF1[byteOf(s1, 1) xor u8(sv, 1)] xor
                    tl[0] xor tED[byteOf(s2, 0) xor u8(sv, 2)] xor tE9[byteOf(s0, 3) xor u8(sv, 3)]
                n1 = tF5[byteOf(s1, 2) xor u8(sv, 4)] xor tF1[byteOf(s2, 1) xor u8(sv, 5)] xor
                    tl[1] xor tED[byteOf(s0, 0) xor u8(sv, 6)] xor tE9[byteOf(s3, 3) xor u8(sv, 7)]
                n2 = tF5[byteOf(s2, 2) xor u8(sv, 8)] xor tF1[byteOf(s0, 1) xor u8(sv, 9)] xor
                    tl[2] xor tED[byteOf(s3, 0) xor u8(sv, 10)] xor tE9[byteOf(s1, 3) xor u8(sv, 11)]
                n3 = tF5[byteOf(s0, 2) xor u8(sv, 12)] xor tF1[byteOf(s3, 1) xor u8(sv, 13)] xor
                    tl[3] xor tED[byteOf(s1, 0) xor u8(sv, 14)] xor tE9[byteOf(s2, 3) xor u8(sv, 15)]
                // state rotation quirk (s0,s1,s2,s3) <- (n0, n2, n3, n1) (17fbfa0-17fc0d3)
                s0 = n0; s1 = n2; s2 = n3; s3 = n1
            }

            // w-block (17fc0d9-17fc311): runs after EVERY round. Only the last round's
            // dwords reach the output bytes — the earlier rounds' results are dead
            // except for the register carry back into the next round's state
            // (esi/edx/ebx/ecx at 17fc311, XORed with the round key at 17fbf4f).
            val w0 = tED[byteOf(n3, 0) xor 0x8f] xor tE9[byteOf(n0, 3) xor 0x10] xor
                tF5[byteOf(n1, 2) xor 0x66] xor tF1[byteOf(n2, 1) xor 0x46] xor 0x397d8245
            val w1 = tED[byteOf(n0, 0) xor 0xb0] xor tE9[byteOf(n1, 3) xor 0x68] xor
                tF5[byteOf(n2, 2) xor 0xcb] xor tF1[byteOf(n3, 1) xor 0x5e] xor 0x18f62871
            val w2 = tED[byteOf(n1, 0) xor 0x9b] xor tE9[byteOf(n2, 3) xor 0xc7] xor
                tF5[byteOf(n3, 2) xor 0x29] xor tF1[byteOf(n0, 1) xor 0x12] xor 0xa06b8293.toInt()
            val w3 = tED[byteOf(n2, 0) xor 0xfd] xor tE9[byteOf(n3, 3) xor 0x31] xor
                tF5[byteOf(n0, 2) xor 0xce] xor tF1[byteOf(n1, 1) xor 0xcf] xor 0xdbc67afb.toInt()
            dwordA = stage2(w3) xor h[3] xor 0xeb34c2c2.toInt()
            dwordB = stage2(w1) xor h[1] xor 0x1d59f5dd
            dwordC = stage2(w0) xor h[0] xor 0x0ba16ca6
            dwordD = stage2(w2) xor h[2] xor 0x13278ca7
            if (round < 5) {
                // register carry (17fc2e1/2ef/2fd + untouched ebx): the carried registers
                // hold stage2(w)^h[xor-carry-const] — i.e. the out dword constants
                // (0x0ba16ca6/0x1d59f5dd/0x13278ca7) are stripped again before the
                // "dead" carry constants 0xc665f28b/0xcf8d9037/0x2c0a2959 are applied
                s0 = (dwordC xor 0x0ba16ca6) xor 0xc665f28b.toInt()
                s1 = (dwordD xor 0x13278ca7) xor 0xcf8d9037.toInt()
                s2 = dwordA
                s3 = (dwordB xor 0x1d59f5dd) xor 0x2c0a2959.toInt()
            }
        }

        // E: finalize via byte table 0x24f9c0 (17fc320-17fc4c3), over the last round's dwords
        val eT = t.byteTable(0x24f9c0)
        fun byteMix(x: Int): Int = (eT[byteOf(x, 0)].toInt() and 0xff) or
            ((eT[byteOf(x, 1)].toInt() and 0xff) shl 8) or
            ((eT[byteOf(x, 2)].toInt() and 0xff) shl 16) or
            ((eT[byteOf(x, 3)].toInt() and 0xff) shl 24)
        val o0 = Integer.reverseBytes(
            byteMix(u32le(ctx, 0x70) xor dwordC xor 0x1507bed6) xor h[4] xor 0xb7e2a921.toInt())
        val o1 = Integer.reverseBytes(
            byteMix(dwordB xor u32le(ctx, 0x74) xor 0xa947bc24.toInt()) xor h[5] xor 0x4367382c.toInt())
        val o2 = Integer.reverseBytes(
            byteMix(dwordD xor u32le(ctx, 0x78) xor 0xafb8d200.toInt()) xor h[6] xor 0x78fe9e63.toInt())
        val o3 = Integer.reverseBytes(
            byteMix(dwordA xor u32le(ctx, 0x7c) xor 0x4471a6d1) xor h[7] xor 0x6a81f99f.toInt())
        val out = ByteArray(16)
        putU32le(out, 0, o0); putU32le(out, 4, o1); putU32le(out, 8, o2); putU32le(out, 12, o3)
        return out
    }

    // ---- gen_otp_ios (0x1801d90) — Mac flavor ----------------------------------

    /**
     * gen_otp_ios's own schedule: like expandSchedule but with sigma terms summed
     * (sigma1 = rotr18+rotr7 - >>>3, sigma0 = rotr19+rotr17; the >>>10 term is XORed
     * into the sum; the whole is subtracted from W[i-16] — 0x1801fc0/0x1801fd4).
     */
    private fun expandScheduleIos(w: IntArray) {
        for (i in 16 until 64) {
            val x = w[i - 2]
            val v = w[i - 15]
            val s1 = rotr(v, 18) + rotr(v, 7) - (v ushr 3)
            val s2 = rotr(x, 19) + rotr(x, 17) xor (x ushr 10)
            w[i] = (s1 xor s2) - w[i - 7] - w[i - 16]
        }
    }

    private class ArxIosResult(val st: IntArray, val out1: Int, val out2: Int)

    /** gen_otp_ios ARX (0x1802100), mixtable 0x2689e0. rot selects the lane rotation. */
    private fun arxIos(w: IntArray, mt: IntArray, init: IntArray, rot2: Boolean): ArxIosResult {
        var a = init[0]; var b = init[1]; var c = init[2]; var d = init[3]
        var e = init[4]; var f = init[5]; var g = init[6]; var h = init[7]
        var out1 = 0; var out2 = 0
        for (i in 0 until 64) {
            // 0x1802100-0x18021xx: the mt term is subtracted, (2g-e-f)^f, rotr11^rotr6
            val eax = mt[i] - 0x076fd9aa - w[i] + rotl(g, 7) -
                (((2 * g - e - f)) xor f) - (rotr(g, 11) xor rotr(g, 6)) + d
            val o1 = (rotr(c, 13) xor rotr(c, 2)) - rotl(c, 10) + (a xor b) -
                ((b + c) xor (a + c)) + eax
            val o2 = eax + h
            out1 = o1; out2 = o2
            if (i == 63) break
            val oa = a; val ob = b; val oc = c; val oe = e; val og = g
            if (rot2) { a = oc; b = oa } else { a = ob; b = oc }
            c = out1; d = f; e = og; f = oe; g = out2; h = if (rot2) ob else oa
        }
        return ArxIosResult(intArrayOf(a, b, c, d, e, f, g, h), out1, out2)
    }

    private val IOS_S1_INIT = intArrayOf(
        0x7c5f6289, 0x593b6cce, -0x3927d65a, -0x338f9db7,
        0x7882d6f2, 0x6f4be3be, 0x750bbed9, -0x06e8dcee,
    )
    private val IOS_S2_INIT = intArrayOf(
        0x593b6cce, 0x7c5f6289, -0x3927d65a, -0x338f9db7,
        0x7882d6f2, 0x6f4be3be, 0x750bbed9, -0x06e8dcee,
    )

    /** out-loop constant-pair index (u16 table at rsp+0x4c0, read backwards). */
    private val SG_CONST = intArrayOf(0, 1, 3, 2)

    /** cascade pxor permutation (pshufd 0xc6 lane map). */
    private val PSH = intArrayOf(2, 1, 0, 3)

    /**
     * gen_otp_ios: IOS-flavor ADI cipher; 16-byte output. `one` = 0xD0 (208) bytes.
     * Transcription of 0x1801d90..0x1804600, verified against the 5 oracle vectors
     * (otp.json keys gen_otp_ios-star; inputs one = LCG(2,208), two = LCG(3,32)).
     */
    internal fun genOtpIos(gen: UInt, one: ByteArray, two: ByteArray): ByteArray {
        val t = ClearAdiTables
        val mt = t.wordTable(0x2689e0, 64)

        // ---- stages 1-3: three ARX passes over two-derived schedules (0x1801e00-0x1802?) --
        val c44 = t.consts16(0x1a3180)
        val c4730 = t.consts16(0x1a4730)
        val c1f30 = t.consts16(0x1a1f30)
        val src = ByteArray(64)
        for (i in 0 until 16) src[i] = (two[i].toInt() xor c44[i].toInt()).toByte()
        for (i in 0 until 16) src[16 + i] = (two[16 + i].toInt() xor c44[i].toInt()).toByte()
        c4730.copyInto(src, 32)
        c1f30.copyInto(src, 48)
        val w1 = IntArray(64)
        for (j in 0 until 16) w1[j] = Integer.reverseBytes(u32le(src, 4 * j)) xor 0x77777777
        expandScheduleIos(w1)
        val r1 = arxIos(w1, mt, IOS_S1_INIT, rot2 = false)
        val a1 = r1.st[0]; val b1 = r1.st[1]; val c1 = r1.st[2]
        val e1 = r1.st[4]; val f1 = r1.st[5]; val g1 = r1.st[6]

        // stage-1 lane material used by the gen section and the key-schedule seed (G)
        val A = a1; val B = b1; val Cp = c1 + 0x593b6cce; val E = e1; val F = f1; val G = g1
        val o1_1 = r1.out1; val o2_1 = r1.out2
        val o2p = o2_1 + 0x750bbed9
        val rr = mapOf(
            "A" to A, "B" to B, "Cp" to Cp, "E" to E, "F" to F, "G" to G,
            "o1" to o1_1, "o2p" to o2p,
        )
        // 15 constant blocks (lane-letter XOR pattern per dword) + 2 hardcoded tail dwords
        val spec = arrayOf(
            0x1a2250 to arrayOf("A", "A", "F", "o2p"), 0x1a1c20 to arrayOf("G", "G", "E", "E"),
            0x1a2c50 to arrayOf("Cp", "o1", "F", "Cp"), 0x1a5850 to arrayOf("F", "B", "B", "A"),
            0x1a3c70 to arrayOf("F", "G", "F", "E"), 0x1a1130 to arrayOf("Cp", "F", "E", "o1"),
            0x1a4cf0 to arrayOf("G", "B", "F", "A"), 0x1a41c0 to arrayOf("A", "o2p", "B", "G"),
            0x1a2f10 to arrayOf("A", "F", "F", "o1"), 0x1a3220 to arrayOf("G", "Cp", "E", "B"),
            0x1a37a0 to arrayOf("Cp", "o2p", "F", "G"), 0x1a4430 to arrayOf("F", "E", "B", "F"),
            0x1a4d00 to arrayOf("F", "Cp", "F", "B"), 0x1a09b0 to arrayOf("Cp", "A", "E", "o2p"),
            0x1a0bf0 to arrayOf("G", "E", "F", "F"),
        )
        val dws = IntArray(64)
        var di = 2
        for ((vaddr, pat) in spec) {
            val cv = t.consts16(vaddr)
            for (i in 0 until 4) {
                dws[di] = rr[pat[i]]!!.toInt() xor u32le(cv, 4 * i)
                di++
            }
        }
        dws[62] = A xor 0xbaf1f4bf.toInt()
        dws[63] = o1_1 xor 0x853efe0b.toInt()

        val X = 0x43e6d7ad.toInt()
        val c2250 = t.consts16(0x1a2250)
        val c5850 = t.consts16(0x1a5850)
        val sh = SHIFT_BYTES
        val buf32 = ByteArray(32)
        buf32[0] = ((((B xor u32le(c5850, 4)) ushr 16) xor 0x43e6) + 0x2a xor Cp xor 0x77).toByte()
        buf32[1] = ((((A xor u32le(c2250, 0)) xor X) ushr 8) + 0x2a xor
            ((A xor u32le(c2250, 4)) ushr 24) xor 0x34).toByte()
        for (j in 2 until 32) {
            val shIdx = 2 * (j and 3)
            val lo = (dws[2 * j] xor X) ushr (sh[shIdx].toInt() and 31)
            val hi = (dws[2 * j + 1] xor X) ushr (sh[shIdx + 1].toInt() and 31)
            buf32[j] = ((lo + 0x2a) xor hi xor 0x77).toByte()
        }

        // ---- stage 2 (buf32 duplicated) ----
        val bufB = ByteArray(64)
        buf32.copyInto(bufB, 0); buf32.copyInto(bufB, 32)
        val w2 = IntArray(64)
        for (j in 0 until 16) w2[j] = Integer.reverseBytes(u32le(bufB, 4 * j)) xor 0x77777777
        expandScheduleIos(w2)
        val r2 = arxIos(w2, mt, IOS_S2_INIT, rot2 = true)
        val a2 = r2.st[0]; val b2 = r2.st[1]; val c2 = r2.st[2]
        val e2 = r2.st[4]; val f2 = r2.st[5]; val g2 = r2.st[6]
        val c1a0ed0 = t.consts16(0x1a0ed0)
        val c1a4a90 = t.consts16(0x1a4a90)
        val c2p = c2 + 0x593b6cce
        val o2p2 = r2.out2 + 0x750bbed9
        val s3Init = intArrayOf(
            a2 xor u32le(c1a0ed0, 8), c2p xor u32le(c1a0ed0, 4), r2.out1 xor u32le(c1a0ed0, 0),
            f2 xor u32le(c1a4a90, 12), g2 xor u32le(c1a4a90, 4), e2 xor u32le(c1a4a90, 8),
            o2p2 xor u32le(c1a4a90, 0), b2 xor u32le(c1a0ed0, 12),
        )

        // ---- stage 3 (padding-block schedule) ----
        val bc = ByteArray(64)
        t.consts16(0x1a3c50).copyInto(bc, 0)
        t.consts16(0x1a4740).copyInto(bc, 16)
        t.consts16(0x1a4740).copyInto(bc, 32)
        t.consts16(0x1a5d90).copyInto(bc, 48)
        val w3 = IntArray(64)
        w3[0] = u32le(bc, 0)
        for (j in 1 until 16) w3[j] = Integer.reverseBytes(u32le(bc, 4 * j)) xor 0x77777777
        expandScheduleIos(w3)
        val r3 = arxIos(w3, mt, s3Init, rot2 = false)
        val a3 = r3.st[0]; val b3 = r3.st[1]; val c3 = r3.st[2]
        val e3 = r3.st[4]; val f3 = r3.st[5]; val g3 = r3.st[6]

        // scatter constants (stage-2 lanes ^ C1a3ea0/C1a0be0)
        val ea0 = t.consts16(0x1a3ea0)
        val be0 = t.consts16(0x1a0be0)
        val s20 = r2.out1 xor u32le(ea0, 0)
        val s30 = a2 xor u32le(ea0, 8)
        val s70 = b2 xor u32le(ea0, 12)
        val s38 = g2 xor u32le(be0, 4)
        val s40 = e2 xor u32le(be0, 8)
        val s50 = f2 xor u32le(be0, 12)

        // ---- gen section: ctx220/230 candidates + 64-byte shuffle region ----
        val o2p2v = r2.out2 + 0x750bbed9
        val A0 = r3.out1 xor s20
        val E0 = e3 xor s40
        val H0 = (c2p + c3) xor 0x43e6d7ad.toInt()
        val B0 = b3 xor s30
        val a3s70 = a3 xor s70
        val G0 = g3 xor s38
        val F0 = f3 xor s50
        val o23p = (r3.out2 + o2p2v) xor 0x43e6d7ad.toInt()
        val ctx220 = intArrayOf(A0, H0, B0, a3s70)
        val ctx230 = intArrayOf(o23p, G0, E0, F0)

        val g = gen.toInt()
        val h1v = (g.toLong() * 0x12e0a56bL) ushr 32
        val t1 = ((g - h1v.toInt()).toLong() and 0xffffffffL)
        val r14v = (t1 ushr 1) + h1v
        val r14w2 = ((r14v ushr 29) and 0xffff).toInt()
        val dx16 = ((g.toLong() * 0x1b39aeb3L) ushr 60 and 0xffff).toInt()
        val cx16 = ((g.toLong() * 0x7b85ee89L) ushr 57 and 0xffff).toInt()
        val r13w = ((g.toLong() * 0x9c715473L) ushr 61 and 0xffff).toInt()
        fun lane16(mult: Int): Int = ((mult + g) and 0xffff) xor 0x7777
        val e0b = lane16(r14w2 * 0x308f)   // esi lane
        val h0b = lane16(dx16 * 0x4467)    // r14 lane
        val b0b = lane16(cx16 * 0xe329)    // r12 lane
        val mVal = (r13w * 0xc259) and 0xffff
        var r9full = (0xffff0000.toInt() or mVal) + g
        r9full = (r9full and 0xffff0000.toInt()) or ((r9full and 0xffff) xor 0x7777)
        val shuf = ByteArray(64)
        shuf[0] = ((e0b ushr 8) and 0xff).toByte(); shuf[1] = (e0b and 0xff).toByte()
        shuf[2] = ((h0b ushr 8) and 0xff).toByte(); shuf[3] = (h0b and 0xff).toByte()
        shuf[4] = ((b0b ushr 8) and 0xff).toByte(); shuf[5] = (b0b and 0xff).toByte()
        shuf[6] = ((r9full ushr 8) and 0xff).toByte()
        val two1 = u8(two, 1)
        val ebx32 = (((two1 xor 0x33) - 0x6d) xor r9full)
        shuf[7] = (ebx32 and 0xff).toByte()
        var chain = ((ebx32 xor 0x77) * 0x44) xor 0xffffff98.toInt()
        val c4740 = t.consts16(0x1a4740)
        c4740.copyInto(shuf, 8); c4740.copyInto(shuf, 24); c4740.copyInto(shuf, 40)
        shuf[55] = 0xf7.toByte()
        for (i in 56 until 62) shuf[i] = 0x77
        shuf[62] = 0x76; shuf[63] = 0xcf.toByte()
        for (k in 0 until 19) {
            val base = 8 + 5 * k
            val ti = 3 + 10 * k
            for (mm in 0 until 5) {
                val n = base + mm
                val qn = ((n.toLong() * 156180629L) ushr 33).toInt()
                val pos = n - 55 * qn
                val tb = u8(two, (ti + 2 * mm) and 0x1f)
                val v = (tb xor 0x33) + (chain xor 0xb)
                val nb = (v and 0xff) xor u8(shuf, pos)
                shuf[pos] = nb.toByte()
                chain = chain xor ((((v and 0xffffff00.toInt()) or nb) xor 0x77) * 0x44)
            }
        }

        // ---- stage 4 (shuffled64 schedule) ----
        val w4 = IntArray(64)
        for (j in 0 until 16) w4[j] = Integer.reverseBytes(u32le(shuf, 4 * j)) xor 0x77777777
        expandScheduleIos(w4)
        val r4 = arxIos(w4, mt, IOS_S2_INIT, rot2 = true)
        val c4p = r4.st[2] + 0x593b6cce
        val o2p4 = r4.out2 + 0x750bbed9
        val ctx240 = intArrayOf(
            r4.out1 xor u32le(ea0, 0), c4p xor 0x43e6d7ad.toInt(),
            r4.st[0] xor u32le(ea0, 8), r4.st[1] xor u32le(ea0, 12),
            o2p4 xor 0x43e6d7ad.toInt(), r4.st[6] xor u32le(be0, 4),
            r4.st[4] xor u32le(be0, 8), r4.st[5] xor u32le(be0, 12),
        )

        // ---- stream: 13 whitbox chunks over `one` (0x1803a00-0x1803a70 region) ----
        val tKey0 = t.byteTable(0x26cfe0); val tKey1 = t.byteTable(0x26cee0)
        val tKey2 = t.byteTable(0x26cce0); val tKey3 = t.byteTable(0x26cde0)
        val tl20 = t.wordTable(0x26d0e0); val tl21 = t.wordTable(0x26d4e0)
        val tl22 = t.wordTable(0x26d8e0); val tl23 = t.wordTable(0x26dce0)
        val tl30 = t.wordTable(0x26e8e0); val tl31 = t.wordTable(0x26e4e0)
        val tl32 = t.wordTable(0x26ece0); val tl33 = t.wordTable(0x26e0e0)
        val tl40 = t.byteTable(0x26f4e0); val tl41 = t.byteTable(0x26cbe0)
        val tl42 = t.byteTable(0x26f5e0); val tl43 = t.wordTable(0x26f0e0)
        fun diag(k16: ByteArray, t0: IntArray, t1: IntArray, t2: IntArray, t3: IntArray,
                 tdw: IntArray): IntArray {
            val out = IntArray(4)
            for (i in 0 until 4) {
                val v = t0[k16[4 * i].toInt() and 0xff] xor
                    t1[k16[4 * ((i + 1) and 3) + 1].toInt() and 0xff] xor
                    t2[k16[4 * ((i + 2) and 3) + 2].toInt() and 0xff] xor
                    t3[k16[4 * ((i + 3) and 3) + 3].toInt() and 0xff]
                out[i] = v xor tdw[i]
            }
            return out
        }
        val c24f0 = t.consts16(0x1a24f0)
        val c4d10 = t.consts16(0x1a4d10)
        val tailC = arrayOf(
            0x1a2a30, 0x1a2c60, 0x1a3a50, 0x1a47d0, 0x1a09c0,
            0x1a2f30, 0x1a3500, 0x1a27a0, 0x1a0ee0,
        ).map { t.consts16(it) }
        val c1140 = t.consts16(0x1a1140)
        val c1700 = t.consts16(0x1a1700)
        // hi_const = le64(0x07ef060b00000000) ‖ le64(0x62181bd1975656c6)
        val hiConst = byteArrayOf(
            0, 0, 0, 0, 0x0b, 6, 0xef.toByte(), 0x07,
            0xc6.toByte(), 0x56, 0x56, 0x97.toByte(), 0xd1.toByte(), 0x1b, 0x18, 0x62,
        )
        val stream = ByteArray(13 * 16)
        var l3dw = IntArray(4) { u32le(t.consts16(0x1a2f20), 4 * it) }
        for (ch in 0 until 13) {
            val o = ch * 16
            val key16 = ByteArray(16)
            for (i in 0 until 4) {
                val b = IntArray(4) { u8(one, o + 4 * i + it) xor u8(c4d10, 4 * i + it) }
                val v = ((tKey0[b[0]].toInt() and 0xff) shl 24) xor
                    ((tKey1[b[1]].toInt() and 0xff) shl 16) xor
                    ((tKey2[b[2]].toInt() and 0xff) shl 8) xor
                    (tKey3[b[3]].toInt() and 0xff) xor u32le(c24f0, 4 * i)
                putU32le(key16, 4 * i, v)
            }
            val k2 = ByteArray(16)
            key16.copyInto(k2, 0, 8, 16); key16.copyInto(k2, 8, 0, 8)
            for (c in 0 until 9) {
                val td = IntArray(4) { u32le(tailC[c], 4 * it) }
                val nv = diag(k2, tl20, tl21, tl22, tl23, td)
                for (i in 0 until 4) putU32le(k2, 4 * i, nv[i])
            }
            val td = IntArray(4) { l3dw[it] xor u32le(c1140, 4 * it) }
            val x16 = diag(k2, tl30, tl31, tl32, tl33, td)
            val x16b = ByteArray(16)
            for (i in 0 until 4) putU32le(x16b, 4 * i, x16[i])
            val mixed = ByteArray(16)
            for (i in 0 until 4) {
                val d = u32le(x16b, 4 * i)
                mixed[4 * i + 0] = tl40[byteOf(d, 3)].toByte()
                mixed[4 * i + 1] = tl41[byteOf(d, 2)].toByte()
                mixed[4 * i + 2] = tl42[byteOf(d, 1)].toByte()
                mixed[4 * i + 3] = (tl43[byteOf(d, 0)] and 0xff).toByte()
            }
            for (i in 0 until 16) stream[o + i] = (hiConst[i].toInt() xor u8(mixed, i)).toByte()
            val keyPrev = IntArray(4) { u32le(key16, 4 * it) }
            l3dw = IntArray(4) { keyPrev[it] xor u32le(c1700, 4 * it) }
        }

        // ---- VM: 192 output bytes from the permuted stream input (0x1803b90-0x1803ca8) --
        val vb = t.vmBlob()
        val c4440 = t.consts16(0x1a4440)
        val sadj = ByteArray(stream.size)
        for (i in stream.indices) sadj[i] = (stream[i].toInt() xor c4440[i and 15].toInt()).toByte()
        val s0seed = (u8(sadj, 0xcd) + u8(sadj, 0x99) + u8(sadj, 0x6b) + u32le(sadj, 0x80))
        var s = s0seed
        val vm = ByteArray(192)
        for (i in 0 until 192) {
            val b = u8(sadj, u32le(vb, 8 * i))
            val m5 = s and 5
            val outB: Int
            when (m5) {
                4 -> { outB = (s + b) and 0xff; s = (((outB) xor (s and 0xff)) - 0x66) }
                1 -> { outB = (b - s) and 0xff; s = (((b - s) xor s) - 0x66) }
                0 -> { outB = (b xor s) and 0xff; s = b - 0x66 }
                else -> { outB = b and 0xff; s = ((b xor s) - 0x66) }
            }
            vm[i] = outB.toByte()
        }

        // ---- ctx assembly ----
        val ctx = ByteArray(0x270)
        for (i in 0 until 4) {
            putU32le(ctx, 0x220 + 4 * i, ctx220[i])
            putU32le(ctx, 0x230 + 4 * i, ctx230[i])
            putU32le(ctx, 0x240 + 4 * i, ctx240[i])
            putU32le(ctx, 0x250 + 4 * i, ctx240[4 + i])
        }
        vm.copyInto(ctx, 0x130)
        // G: ctx[0x200..0x220] — stage-1 derived dwords (17fbd39-adjacent stores)
        val c24e0 = t.consts16(0x1a24e0)
        val c2240 = t.consts16(0x1a2240)
        val gd = intArrayOf(
            o1_1 xor u32le(c24e0, 0),
            Cp xor u32le(c24e0, 4),
            B xor u32le(c24e0, 8),
            A xor u32le(c24e0, 12),
            o2p xor u32le(c2240, 0),
            G xor u32le(c2240, 4),
            E xor u32le(c2240, 8),
            F xor u32le(c2240, 12),
        )
        for (i in 0 until 8) putU32le(ctx, 0x200 + 4 * i, gd[i])
        // ctx[0x120..0x130] = bswap(vm[0..16]); ctx[0x70+4i] = bswap(vm[0x10+4i])
        for (j in 0 until 4) {
            ctx[0x120 + 4 * j + 0] = vm[4 * j + 3]; ctx[0x120 + 4 * j + 1] = vm[4 * j + 2]
            ctx[0x120 + 4 * j + 2] = vm[4 * j + 1]; ctx[0x120 + 4 * j + 3] = vm[4 * j + 0]
        }
        for (i in 0 until 40) {
            for (k in 0 until 4) ctx[0x70 + 4 * i + k] = vm[0x10 + 4 * i + 3 - k]
        }

        // ---- key schedule (0x1803e90-0x1804006) ----
        val ks1 = arrayOf(t.wordTable(0x26bbe0), t.wordTable(0x26c7e0), t.wordTable(0x26c3e0), t.wordTable(0x26bfe0))
        val ks2 = arrayOf(t.wordTable(0x26abe0), t.wordTable(0x26afe0), t.wordTable(0x26b3e0), t.wordTable(0x26b7e0))
        val firstMask = t.raw(0x268980, 96)
        val secondMask = t.raw(0x268920, 96)
        val finalMask = t.raw(0x2688c0, 96)
        val K = IntArray(24)
        for (i in 0 until 24) {
            var x = u32le(ctx, 0x200 + 4 * i) xor u32le(firstMask, 4 * i)
            if (i < 4) x = x xor u32le(ctx, 0x120 + 4 * i)
            val t1v = mix4(x, ks1[0], ks1[1], ks1[2], ks1[3]) xor u32le(secondMask, 4 * i)
            val t2v = mix4(t1v, ks2[0], ks2[1], ks2[2], ks2[3])
            var k = t2v xor u32le(finalMask, 4 * i)
            if (i < 4) k = k xor u32le(ctx, 0x70 + 4 * i)
            K[i] = k
        }

        // ---- rounds: 6 × (9-step AES-T cascade + post-mix + out) (0x18040e0-0x18044ec) --
        val rtA = t.wordTable(0x26a7e0); val rtB = t.wordTable(0x269be0)
        val rtC = t.wordTable(0x26a3e0); val rtD = t.wordTable(0x269fe0)
        val m40 = t.wordTable(0x2693e0); val m41 = t.wordTable(0x268be0)
        val m42 = t.wordTable(0x2697e0); val m43 = t.wordTable(0x268fe0)
        val ksConsts = arrayOf(
            0x1a5590, 0x1a5da0, 0x1a5db0, 0x1a47e0, 0x1a2a40,
            0x1a2c70, 0x1a19c0, 0x1a5860, 0x1a1c30,
        ).map { t.consts16(it) }
        // W: byte picks from the VM input (sadj = stream ^ C4440*13) + the VM state
        // seed low byte; written to ctx[0x110..0x120] by the binary (0x1803d0b-0x1803dd0)
        val s0seedLow = (u8(sadj, 0x8a) - s0seed) and 0xff
        val wA = (u8(sadj, 0x49) shl 24) or (u8(sadj, 0x00) shl 16) or
            (u8(sadj, 0x20) shl 8) or u8(sadj, 0x90)
        val wB = (s0seedLow shl 24) or (u8(sadj, 0x1c) shl 16) or
            (u8(sadj, 0x7b) shl 8) or u8(sadj, 0x9a)
        val wC = (u8(sadj, 0xba) shl 24) or (u8(sadj, 0x38) shl 16) or
            (u8(sadj, 0x9e) shl 8) or u8(sadj, 0x25)
        val wD = (u8(sadj, 0xcd) shl 24) or (u8(sadj, 0x99) shl 16) or
            (u8(sadj, 0x80) shl 8) or u8(sadj, 0x6b)
        val wv = intArrayOf(wA, wC, wD, wB)
        val yv = IntArray(4) { wv[it] xor u32le(t.consts16(0x1a5030), 4 * it) }
        val c0f00 = t.consts16(0x1a0f00)
        var prev = intArrayOf(0x28c8ecaf, 0x2cf27d71, 0x18affa28, 0x499e4844)
        var mem = IntArray(4)
        for (r in 0 until 6) {
            val d0 = prev[0] xor K[4 * r] xor 0xad69d16a.toInt()
            val d1 = prev[1] xor K[4 * r + 1] xor 0xa95340b4.toInt()
            val d2 = prev[2] xor K[4 * r + 2] xor 0x9d0ec7ed.toInt()
            val d3 = prev[3] xor K[4 * r + 3] xor 0xcc3f7581.toInt()
            var eb = d1; var ec = d0; var ed = d2; var ea = d3
            var o = IntArray(4)
            for (k in 0 until 9) {
                // aessmix (0x18041df-0x18042bf): RT tables r8/rsi/r15/r12
                o = intArrayOf(
                    rtA[byteOf(eb, 0)] xor rtB[byteOf(ed, 3)] xor rtC[byteOf(ec, 1)] xor rtD[byteOf(ea, 2)],
                    rtA[byteOf(ec, 0)] xor rtB[byteOf(eb, 3)] xor rtC[byteOf(ea, 1)] xor rtD[byteOf(ed, 2)],
                    rtA[byteOf(ea, 0)] xor rtB[byteOf(ec, 3)] xor rtC[byteOf(ed, 1)] xor rtD[byteOf(eb, 2)],
                    rtA[byteOf(ed, 0)] xor rtB[byteOf(ea, 3)] xor rtC[byteOf(eb, 1)] xor rtD[byteOf(ec, 2)],
                )
                val px = o
                for (j in 0 until 4) {
                    // pshufd 0xc6 of the ctx chunk + blobc chunk
                    val xk = Integer.reverseBytes(u32le(vm, 0x20 + 0x10 * k + 4 * PSH[j]))
                    o[j] = px[j] xor xk xor u32le(ksConsts[k], 4 * j)
                }
                val t0 = o[1]; val t1v = o[2]; val t2v = o[0]; val t3v = o[3]
                eb = t0; ec = t1v; ed = t2v; ea = t3v
            }
            // post-mix (0x18042e0-0x180441b): RT lanes over the cascade output
            val stv = IntArray(4) { j ->
                rtA[byteOf(o[j], 0)] xor rtB[byteOf(o[(j + 3) and 3], 3)] xor
                    rtC[byteOf(o[(j + 1) and 3], 1)] xor rtD[byteOf(o[(j + 2) and 3], 2)]
            }
            val c1150 = t.consts16(0x1a1150)
            val state = IntArray(4) { stv[it] xor u32le(c1150, 4 * it) }
            for (j in 0 until 4) {
                val kk = SG_CONST[j]
                val v = m40[byteOf(state[j], 0)] xor m41[byteOf(state[j], 1)] xor
                    m42[byteOf(state[j], 2)] xor m43[byteOf(state[j], 3)]
                mem[j] = v xor u32le(c0f00, 4 * kk) xor yv[kk]
            }
            prev = intArrayOf(mem[3], mem[2], mem[1], mem[0])
        }

        // ---- final (0x18044f2-0x18045c3) ----
        val preout = intArrayOf(
            mem[3], mem[2], mem[1], mem[0] xor 0x6145cbf9.toInt(),
        )
        val c5040 = t.consts16(0x1a5040)
        val c2500 = t.consts16(0x1a2500)
        val feist = t.byteTable(0x268ae0)
        val out = ByteArray(16)
        for (j in 0 until 4) {
            val tv = preout[j] xor u32le(c5040, 4 * j) xor u32le(ctx, 0x70 + 4 * j)
            val ft = ByteArray(16)
            for (i in 0 until 4) ft[i] = feist[byteOf(tv, i)].toByte()
            val v = u32le(c2500, 4 * j) xor u32le(ctx, 0x120 + 4 * j) xor u32le(ft, 0)
            putU32le(out, 4 * j, Integer.reverseBytes(v))
        }
        return out
    }

    // ---- gen_code (0x1801360) ---------------------------------------------------

    /**
     * gen_code: SHA-1(sig ‖ machine[0x38..0x74]) — the full 60-byte secret, two standard
     * blocks (the report's "48 bytes" is wrong: block 2 carries machine[0x68..0x74] plus
     * padding, length 608 bits, 0x18013a2/0x18013bb/0x18013ef). Returns
     * ((h0<<32)|h1) mod 1_000_000 (0x1801414-0x1801443).
     */
    internal fun genCode(sig: ByteArray, secret60: ByteArray): UInt {
        require(secret60.size >= 60) { "secret must be 60 bytes" }
        val md = java.security.MessageDigest.getInstance("SHA-1")
        val input = ByteArray(16 + 60)
        sig.copyInto(input, 0)
        secret60.copyInto(input, 16, 0, 60)
        val d = md.digest(input)
        val h0 = ((d[0].toInt() and 0xff) shl 24) or ((d[1].toInt() and 0xff) shl 16) or
            ((d[2].toInt() and 0xff) shl 8) or (d[3].toInt() and 0xff)
        val h1 = ((d[4].toInt() and 0xff) shl 24) or ((d[5].toInt() and 0xff) shl 16) or
            ((d[6].toInt() and 0xff) shl 8) or (d[7].toInt() and 0xff)
        val h01 = (h0.toLong() and 0xffffffffL) shl 32 or (h1.toLong() and 0xffffffffL)
        return (h01 % 1_000_000L).toInt().toUInt()
    }

    // ---- frame builders (generate_sig 0x17eead0 / generate_otp 0x17ee2a0 / gen_2fa_code) --

    /** 28-byte X-Apple-I-MD payload: u32be(5) ‖ u32be(16) ‖ sig16 ‖ u32be(flavor). */
    fun anisetteOtp(flavor: Int, metadata: ByteArray, mid: ByteArray, unixSeconds: Long): ByteArray {
        val gen = (unixSeconds / 30).toInt().toUInt()
        // `metadata` feeds the cipher as `one` = the machine's client_info (≥ 0x190 B IOS /
        // ≥ 0xd0 B Mac, otp-path.md §3). Until the live capture pins the
        // ProvisionedData→client_info mapping, shorter inputs are zero-extended to the
        // flavor's minimum (deterministic placeholder). TODO(live-capture)
        val need = if (flavor == 1) 0x190 else 0xd0
        val one = if (metadata.size >= need) metadata else metadata + ByteArray(need - metadata.size)
        // flavor 1 (IOS) -> gen_otp; flavor 0 (Mac) -> gen_otp_ios (naming inverted in the binary)
        val sig = when (flavor) {
            1 -> genOtp(gen, one, mid)
            else -> genOtpIos(gen, one, mid)
        }
        val out = ByteArray(28)
        out[0] = 0; out[1] = 0; out[2] = 0; out[3] = 5
        out[4] = 0; out[5] = 0; out[6] = 0; out[7] = 16
        sig.copyInto(out, 8)
        out[24] = 0; out[25] = 0
        out[26] = (flavor ushr 8).toByte(); out[27] = flavor.toByte()
        return out
    }

    /** 2FA code for the current 30-second window. `secret` = machine[0x38..0x74] (60 B). */
    fun twoFactorCode(
        flavor: Int,
        metadata: ByteArray,
        mid: ByteArray,
        secret: ByteArray,
        unixSeconds: Long,
    ): UInt {
        val frame = anisetteOtp(flavor, metadata, mid, unixSeconds)
        return genCode(frame.copyOfRange(8, 24), secret)
    }
}
