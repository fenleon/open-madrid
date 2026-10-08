package dev.fenn.imessage.registration

import kotlin.test.Test
import kotlin.test.assertContentEquals

/**
 * Synthetic vectors for the pear_aes port: inputs are deterministic LCG streams (same
 * helper as ClearAdiOtpTest); expected outputs were computed with the verified Python
 * models (pear.py / dec_model.py, byte-exact vs live captures).
 */
class PearAesTest {

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
        ByteArray(s.length / 2) { ((Character.digit(s[it * 2], 16) shl 4) or
            Character.digit(s[it * 2 + 1], 16)).toByte() }

    private fun toHex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }


    @Test
    fun initKeyMatchesModel() {
        val expected = mapOf(
        11 to Pair("e88e85d301b9d830a6436b2ce791ac10", "b070633c97832f9f9cc42839766f18d9911fbb11069c948e9a58bcb7ec37a46e6902bc5b6f9e28d5f5c6946219f1300c6da5fb6e023bd3bbf7fd47d9ee0c77d5808f16aa82b4c511754982c89b45f51d7581e433f7352122827ca3ea193956f746e78506b1d2a42433ae07ce2a975139a693f0251741540124ef53cf0e7802f62de8409a3aa9149b1e464754103e45a271c4b76f4b6da3f4552be4a04515a102f61bcc43bd766fb7e85d8b17ad482a15"),
        12 to Pair("55dd4b156a537bf35b00e9acf810b3fe", "e66d6e9bbf1df17ab700271869d90792a9bec37116a3320ba1a31513c87a12816f7022c679d310cdd87005de100a175fbf780b33c6ab1bfe1edb1e200ed1097f3e5f998cf8f48272e62f9c52e8fe952d22fcf165da0873173c27ef45d4d97a68bc14b054661cc3435a3b2c068ee2566ef272b7d5946e7496ce55589040b70efe71cd7259e5a306cf2bf65e5f6b4150a1411aad90a4b9ab5f8f4ff500e40ea5a19aa972c03e10d99fb15f2c9f5551893e"),
        )
        for ((seed, kv) in expected) {
            assertContentEquals(hex(kv.second), PearAes.initKey(hex(kv.first)), "seed=$seed")
        }
    }

    @Test
    fun establishKeyMatchesModel() {
        val expected = mapOf(
        13 to Pair("c22b1257d3ed1db610bd662d0990b9ec", "c22b1257d3ed1db610bd662d0990b9ec9c4f2212400ff2cb42a982f98b7352f6ed29a131ad2653faef8fd10364fc83f566c4412dcbe212d7246dc3d4409140218c3c103647de02e163b3c13523228114113d374256e335a33550f4961672758294a04ba4c2437e07f7138a91e161ff1315db4510d7983b17208bb186c1ea4e9557bcf69d8024cd8aa0af7c0c6145329937a56f30b781a2ba172edeb6766bec2ff17a6c23b520a5da52ad7733451990a9"),
        14 to Pair("2f7ad8983c88c078c579e4ad1a0fc0da", "2f7ad8983c88c078c579e4ad1a0fc0da03357730fffdd5aab875bbfe5f62fa4054e6dabbab1b0f11136eb4ef4c0c4eaf6b4dcd6dc056c27cd33876939f34383c34313145f467f339275f85aab86bbd96c9ebe5993d8c16a01ad3930aa2b82e9c04101c4a399c0aea234f99e081f7b77cbd4679b584da735fa795eabf26625dc3731c9c0af7c6ef55505305ea763158298e1b477779dda822298eadc85fbff5e11d51268abe40ccfc7ff99319f4d575ac"),
        )
        for ((seed, kv) in expected) {
            assertContentEquals(hex(kv.second), PearAes.establishKey(hex(kv.first)), "seed=$seed")
        }
    }

    @Test
    fun encryptCbcDecryptCbcMatchModel() {
        val key = hex("2a9f44651bc132cbb8a254319188ed5c")
        val rk = PearAes.initKey(key)
        val pt = hex("97ed0aa7845bd58d6d5fd2b1a207f44a33cc864df0ab0ef769854295eefb2eaa8ff8d70e1c974aad250f757efae8129e")
        val iv = hex("043cd1e8edf57750221c5032b386fa38")
        val ct = hex("16255fdcc2e2443839bbe9075313aae089309473c2f05d09ea8f03698056680de94fc8a870208cf435d0b282cf4c3a65")
        assertContentEquals(ct, PearAes.encryptCbc(pt, iv, rk))
    }

    @Test
    fun decryptCbcMatchesModel() {
        val rk = hex("e66d6e9bbf1df17ab700271869d90792a9bec37116a3320ba1a31513c87a12816f7022c679d310cdd87005de100a175fbf780b33c6ab1bfe1edb1e200ed1097f3e5f998cf8f48272e62f9c52e8fe952d22fcf165da0873173c27ef45d4d97a68bc14b054661cc3435a3b2c068ee2566ef272b7d5946e7496ce55589040b70efe71cd7259e5a306cf2bf65e5f6b4150a1411aad90a4b9ab5f8f4ff500e40ea5a19aa972c03e10d99fb15f2c9f5551893e")
        val ct = hex("718a972a56901a13d7d8cdb2c4050127ad5cc924e25bc79e732badcb30baea49")
        val iv = hex("ded85d6cbf2abdd58c954b33d5840715")
        val pt = hex("8a57f1d423d4c63f6f0e4dd54e5c9275464fb252764c3679675b4371e169601b")
        assertContentEquals(pt, PearAes.decryptCbc(ct, iv, rk))
    }

    @Test
    fun decryptCbcMatchesModelVector2() {
        val rk = hex("e66d6e9bbf1df17ab700271869d90792a9bec37116a3320ba1a31513c87a12816f7022c679d310cdd87005de100a175fbf780b33c6ab1bfe1edb1e200ed1097f3e5f998cf8f48272e62f9c52e8fe952d22fcf165da0873173c27ef45d4d97a68bc14b054661cc3435a3b2c068ee2566ef272b7d5946e7496ce55589040b70efe71cd7259e5a306cf2bf65e5f6b4150a1411aad90a4b9ab5f8f4ff500e40ea5a19aa972c03e10d99fb15f2c9f5551893e")
        val ct = hex("4b2724ae28c55f984152c9b3e6030e0327ed0bfcd40b80467dd117027278a6e9c334c04e4011bc697908d5e9bea9dfbe")
        val iv = hex("b875eaef915f025bf60e4734f78214f1")
        val pt = hex("312b7ef3df509cf09e612c63ad72e4a908160da4c95e0b3b3ea9d7ef48bd03ecda19b9c084652266fbdbc93a220ef9e7")
        assertContentEquals(pt, PearAes.decryptCbc(ct, iv, rk))
    }
}
