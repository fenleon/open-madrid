package dev.fenn.imessage.registration

/**
 * Kotlin transcription of the NAC merge layer (open_absinthe::nac domergestep2 /
 * scramble_body, librust_lib_bluebubbles). domergestep2 is verified byte-exact against
 * 21 live captures; scramble_body reproduces ValidationCtx::sign's session-material
 * whitening. Ported from nac_mint.py (NAC-NOTES.md); the domerge constants are pulled
 * from the verified model.
 */
internal object NacMerge {

    /** domerge block constants CC[m][j] (nac_mint.py). */
    private val CC = intArrayOf(0x01, 0x02, 0x03, 0x04, 0x52, 0x53, 0x54, 0x55, 0xa3, 0xa4, 0xa5, 0xa6, 0xf4, 0xf5, 0xf6, 0xf7)

    /**
     * domergestep2(in1, in2): out[0..64) = mix(in2[0..64) || IV2) xor in1[0..64), where
     * mix over the 80-byte state is:
     * 1. state[a] = KP[(state[a]+a)&0xff] + a  (a = 0..79)
     * 2. four blocks m = 0..3:
     *      state[0] ^= TB[state[0x37]] + TA[state[0x4b]] + 0x51*m
     *      state[1+j] ^= TB[state[0x38+j]] + TA[state[0x4c+j]] + CC[m][j]   (j < 4)
     *      state[i] ^= TA[state[i-5]] + TB[state[(i-0x19)%80]] + i + 0x51*m (i = 5..0x4f)
     * 3. state[k] = TC[state[k]] + k  (k = 0..79)
     * (TA/TB/TC/KP = 0x224d22/0x224e22/0x224c22/0x224f22, IV2 = 0x1a0ea0.)
     */
    internal fun domergeStep2(in1: ByteArray, in2: ByteArray): ByteArray {
        require(in1.size >= 64 && in2.size >= 64) { "domergestep2: need two 64-byte blocks" }
        val ta = PearTables.dma
        val tb = PearTables.dmb
        val tc = PearTables.dmc
        val kp = PearTables.kp
        val st = ByteArray(80)
        in2.copyInto(st, 0, 0, 64)
        PearTables.iv2.copyInto(st, 64)
        for (a in 0 until 80) {
            st[a] = ((kp[(st[a].toInt() and 0xff) + a and 0xff].toInt() and 0xff) + a)
                .and(0xff).toByte()
        }
        for (m in 0 until 4) {
            val x0 = ((tb[st[0x37].toInt() and 0xff].toInt() and 0xff) +
                (ta[st[0x4b].toInt() and 0xff].toInt() and 0xff) + 0x51 * m) and 0xff
            st[0] = (st[0].toInt() xor x0).toByte()
            for (j in 0 until 4) {
                val x = ((tb[st[0x38 + j].toInt() and 0xff].toInt() and 0xff) +
                    (ta[st[0x4c + j].toInt() and 0xff].toInt() and 0xff) + CC[4 * m + j]) and 0xff
                st[1 + j] = (st[1 + j].toInt() xor x).toByte()
            }
            for (i in 5 until 0x50) {
                val p = (i - 0x19).mod(80)
                val x = ((ta[st[i - 5].toInt() and 0xff].toInt() and 0xff) +
                    (tb[st[p].toInt() and 0xff].toInt() and 0xff) + i + 0x51 * m) and 0xff
                st[i] = (st[i].toInt() xor x).toByte()
            }
        }
        for (k in 0 until 0x50) {
            st[k] = ((tc[st[k].toInt() and 0xff].toInt() and 0xff) + k and 0xff).toByte()
        }
        val out = ByteArray(64)
        for (i in 0 until 64) out[i] = (st[i].toInt() xor in1[i].toInt()).toByte()
        return out
    }

    /**
     * scramble_body(data, rngPad): buffer = [u32be len][data][rngPad] (len 1..0x17c, padded
     * to 0x180 bytes), then three independent 7-call domergestep2 chains over the block
     * pairs (b0,b1) (b2,b3) (b4,b5); each pair is replaced by that chain's (t6, t7).
     * Returns 384 bytes.
     */
    internal fun scrambleBody(data: ByteArray, rngPad: ByteArray): ByteArray {
        val n = data.size
        require(n in 1..0x17c) { "scramble_body: data length must be 1..0x17c" }
        require(n + rngPad.size == 0x17c) { "scramble_body: rngPad must fill the block" }
        val buf = ByteArray(0x180)
        putU32be(buf, 0, n)
        data.copyInto(buf, 4)
        rngPad.copyInto(buf, 4 + n)
        val out = ByteArray(0x180)
        var o = 0
        for (start in intArrayOf(0, 128, 256)) {
            group7(buf, start, start + 64).copyInto(out, o)
            o += 128
        }
        return out
    }

    /** 7-call domergestep2 chain over two 64-B blocks; returns (t6, t7) = 128 bytes. */
    private fun group7(buf: ByteArray, a0: Int, b0: Int): ByteArray {
        val a = buf.copyOfRange(a0, a0 + 64)
        val b = buf.copyOfRange(b0, b0 + 64)
        val t1 = domergeStep2(a, b)
        val t2 = domergeStep2(b, t1)
        val t3 = domergeStep2(t1, t2)
        val t4 = domergeStep2(t2, t3)
        val t5 = domergeStep2(t3, t4)
        val t6 = domergeStep2(t4, t5)
        val t7 = domergeStep2(t5, t6)
        return t6 + t7
    }

    private fun putU32be(b: ByteArray, off: Int, v: Int) {
        b[off] = (v ushr 24).toByte()
        b[off + 1] = (v ushr 16).toByte()
        b[off + 2] = (v ushr 8).toByte()
        b[off + 3] = v.toByte()
    }
}
