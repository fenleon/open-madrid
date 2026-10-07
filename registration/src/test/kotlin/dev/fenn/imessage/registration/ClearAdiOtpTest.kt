package dev.fenn.imessage.registration

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * Golden vectors captured from the reference white-box via a local ctypes oracle
 * (dev-only; inputs are the deterministic LCG streams of /tmp/clearadi-re/oracle.py).
 */
class ClearAdiOtpTest {

    private fun stream(seed: Int, n: Int): ByteArray {
        val out = ArrayList<Byte>(n)
        var x = seed.toLong() and 0xffffffffL
        while (out.size < n) {
            x = (1103515245L * x + 12345L) and 0xffffffffL
            out.add((x and 0xff).toByte())
            out.add(((x ushr 8) and 0xff).toByte())
            out.add(((x ushr 16) and 0xff).toByte())
            out.add(((x ushr 24) and 0xff).toByte())
        }
        return out.toByteArray().copyOf(n)
    }

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { ((Character.digit(s[it * 2], 16) shl 4) or Character.digit(s[it * 2 + 1], 16)).toByte() }

    private fun toHex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    private val one400 = stream(1, 0x190)
    private val one208 = stream(2, 0xD0)
    private val two32 = stream(3, 32)

    // ---- tables.json ----

    private val gentableExpected = hex(
        "15c3bd38a696ba62679c556a977f711ed5a108e600a6c0a568d8293b98e803c2" +
            "a0b915578171b4e616ad03305ad15dbcfa1393f404be058ce834a7c8aa67b493" +
            "d0ce116c2d953961d97c248190638d43fd48b29375106a356469d36498b95426" +
            "043467b08038d02edd6994f63ac0d8207634d32e434ab71368de32ae66480ff6" +
            "b87f3e981620118f6bffebe1e7d93d563fc2be3bae2e4fbc79f3c342723fe8c0" +
            "649f663c66d9127388a75b7082230791931f9cf1a5d0ebe0942d4801d6be68e3" +
            "397e22c7c780f3c2d9d40ea65773063262bc92c6aec24a4b441ac4e55e91907a" +
            "bcf1e911a8afe98be888c801a40911ccca39156e2e059f6974b0d928d9222c49" +
            "a6890936b479aa2dc2eac9833cd3a18230e36f9dc9442b4679527fdc37b1a2c3" +
            "5f23c680f9256a17a063d8fa8f00b5c9f06287756af01dcb2c054cc8d2f5d7dc" +
            "05edf58ae5e9dad658fea553b4e4dd335ec6443de4b736b8d8b9d4884d7fd4df" +
            "098ad959b06985e02b255367381cc53e52c17c971ac860621d37b8a50e0f0e16"
    )

    private val gensourceExpected = mapOf(
        0u to hex(
            "2eeaa70b34574c7e98474a24904c5d8976f987bf8457ad10e7eee5f44be2421c" +
                "910451b7c13440ee8704e7beeca9c9c330d50baf6100bd06853b65dd6ff95abc" +
                "6ff81fa1be6591beb67a7447ff1b6ce1986fdd5265e81383e2f0a5b850da1f20"
        ),
        1u to hex(
            "2eeaa70b34574c7e98474a24904c5d8976f987bf8457ad10e7eee5f44be2421c" +
                "910451b7c13440ee8704e7beeca9c9c330d50baf6100bd06853b65dd6ff95abc" +
                "6dcacca23c3b4404cb920ce9f826f7b98173917ef6aa372e8cff4d6c5929e889"
        ),
        12345u to hex(
            "2eeaa70b34574c7e98474a24904c5d8976f987bf8457ad10e7eee5f44be2421c" +
                "910451b7c13440ee8704e7beeca9c9c330d50baf6100bd06853b65dd6ff95abc" +
                "7174088a2ee0687227a1c64eab240e0964c4d866d1dc8b869c9d0e2f5366dfe5"
        ),
    )

    @Test
    fun gentableMatchesOracle() {
        val ctx = ByteArray(0x320)
        ClearAdiOtp.genTable(ctx, one400)
        assertContentEquals(gentableExpected, ctx.copyOfRange(0x130, 0x2b0))
    }

    @Test
    fun gensourceMatchesOracle() {
        for ((gen, expected) in gensourceExpected) {
            val ctx = ByteArray(0x320)
            ClearAdiOtp.genSource(ctx, two32, gen)
            assertContentEquals(expected, ctx.copyOfRange(0x2c0, 0x320), "gen=$gen")
        }
    }

    // ---- otp.json (gen_otp / IOS flavor) ----

    private val genOtpExpected = mapOf(
        0u to "00669cc21c0bd8a670b5959ce58a87bf",
        1u to "e6f70fc4fdb2435a935651582b9c970a",
        12345u to "3bb75405b8512c3f56ec6b824172f26d",
        1467106968u to "14699fcb5b79c8808a3e01334b5f845e",
        375889u to "3878efa22001c4d7f90215088f2e303a",
    )

    @Test
    fun genOtpMatchesOracle() {
        for ((gen, expected) in genOtpExpected) {
            val out = ClearAdiOtp.genOtp(gen, one400, two32)
            assertEquals(expected, toHex(out), "gen=$gen")
        }
    }

    @Test
    fun genOtpReadsOnlyFirst0x190BytesOfOne() {
        // oracle cross-check: gen_otp(gen=12345, one400+one208) == gen_otp(gen=12345, one400)
        val out = ClearAdiOtp.genOtp(12345u, one400 + one208, two32)
        assertEquals("3bb75405b8512c3f56ec6b824172f26d", toHex(out))
    }

    // ---- gen_code (0x1801360) ----

    @Test
    fun genCodeIsSha1OverSigAnd60ByteSecret() {
        val sig = stream(5, 16)
        val secret = stream(4, 60)
        val md = java.security.MessageDigest.getInstance("SHA-1")
        val expected = md.digest(sig + secret)
        val h0 = ((expected[0].toInt() and 0xff) shl 24) or ((expected[1].toInt() and 0xff) shl 16) or
            ((expected[2].toInt() and 0xff) shl 8) or (expected[3].toInt() and 0xff)
        val h1 = ((expected[4].toInt() and 0xff) shl 24) or ((expected[5].toInt() and 0xff) shl 16) or
            ((expected[6].toInt() and 0xff) shl 8) or (expected[7].toInt() and 0xff)
        val h01 = ((h0.toLong() and 0xffffffffL) shl 32) or (h1.toLong() and 0xffffffffL)
        assertEquals(((h01 % 1_000_000L).toInt()).toUInt(), ClearAdiOtp.genCode(sig, secret))
    }

    // ---- frame shape (generate_otp 0x17ee2a0) ----

    @Test
    fun anisetteOtpFrameLayout() {
        val t = 1_700_000_123L // fixed time -> gen = t/30
        val frame = ClearAdiOtp.anisetteOtp(1, one400, two32, t)
        assertEquals(28, frame.size)
        assertEquals(5, ((frame[0].toInt() and 0xff) shl 24) or ((frame[1].toInt() and 0xff) shl 16) or
            ((frame[2].toInt() and 0xff) shl 8) or (frame[3].toInt() and 0xff))
        assertEquals(16, ((frame[4].toInt() and 0xff) shl 24) or ((frame[5].toInt() and 0xff) shl 16) or
            ((frame[6].toInt() and 0xff) shl 8) or (frame[7].toInt() and 0xff))
        assertEquals(1, frame[27].toInt() and 0xff)
        val expectedSig = ClearAdiOtp.genOtp((t / 30).toInt().toUInt(), one400, two32)
        assertContentEquals(expectedSig, frame.copyOfRange(8, 24))
    }

    @Test
    fun twoFactorCodeMatchesGenCodeOfFrameSig() {
        val t = 1_700_000_123L
        val secret = stream(4, 60)
        val frame = ClearAdiOtp.anisetteOtp(1, one400, two32, t)
        val expected = ClearAdiOtp.genCode(frame.copyOfRange(8, 24), secret)
        assertEquals(expected, ClearAdiOtp.twoFactorCode(1, one400, two32, secret, t))
    }

    // ---- gen_otp_ios (Mac flavor) ----

    @Test
    fun genOtpIosMatchesOracle() {
        val expected = mapOf(
            0u to "7dfb116f698533c668332b936158feb5",
            1u to "3cd08c5ff781a4778cd971933b12a658",
            12345u to "1b971539b155d6da131dab2c237374f7",
            1467106968u to "2fbf0ad480a1c05716725c7146c0ae17",
            375889u to "404ff1905e7fab582b19a6ed77d168a7",
        )
        assertEquals(5, expected.size)
        for ((gen, hex) in expected) {
            val got = toHex(ClearAdiOtp.genOtpIos(gen, one208, two32))
            assertEquals(hex, got, "gen=$gen")
        }
    }

    @Test
    fun anisetteOtpMacFlavorUsesGenOtpIos() {
        val frame = ClearAdiOtp.anisetteOtp(0, one208, two32, 0L)
        val expected = ClearAdiOtp.genOtpIos(0u, one208, two32)
        assertContentEquals(expected, frame.copyOfRange(8, 24))
        assertEquals(0, frame[26].toInt()); assertEquals(0, frame[27].toInt())
    }
}
