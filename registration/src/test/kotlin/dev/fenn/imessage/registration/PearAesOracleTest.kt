package dev.fenn.imessage.registration

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertTrue

/** Session-40: the Kotlin decryptCbc against the .so's own live oracle session. */
class PearAesOracleTest {

    private fun res(name: String): ByteArray = when (name) {
        "oracle-estkey-arg.bin" -> PearOracleVectors.estkeyarg
        "oracle-estkey-ret.bin" -> PearOracleVectors.estkeyret
        "oracle-sessinfo.bin" -> PearOracleVectors.sessinfo
        else -> PearOracleVectors.body576
    }

    @Test
    fun establishKeyMatchesTheSo() {
        val pear16 = res("oracle-estkey-arg.bin").copyOfRange(0, 16)
        val rk = PearAes.establishKey(pear16)
        val ret = res("oracle-estkey-ret.bin")
        assertTrue(ret.copyOfRange(0, 176).contentEquals(rk), "establishKey rounds")
    }

    @Test
    fun decryptCbcReproducesTheSoBody576() {
        val pear16 = res("oracle-estkey-arg.bin").copyOfRange(0, 16)
        val sess = res("oracle-sessinfo.bin")
        val rk = PearAes.establishKey(pear16)
        val key16 = sess.copyOfRange(1, 17)
        val bodyLen = ((sess[17].toInt() and 0xff) shl 24) or ((sess[18].toInt() and 0xff) shl 16) or
            ((sess[19].toInt() and 0xff) shl 8) or (sess[20].toInt() and 0xff)
        val iv = ByteArray(16) { PearTables.skey[key16[it].toInt() and 0xff] }
        val ct = ByteArray(bodyLen) { i -> PearTables.skey[sess[21 + i].toInt() and 0xff] }
        val pt = PearAes.decryptCbc(ct, iv, rk)
        val pt2 = ByteArray(pt.size) { i -> PearTables.sdat[pt[i].toInt() and 0xff] }
        val expect = res("oracle-body576.bin")
        assertContentEquals(expect, pt2.copyOfRange(2, 2 + expect.size))
    }
}
