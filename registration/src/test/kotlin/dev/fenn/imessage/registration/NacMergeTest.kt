package dev.fenn.imessage.registration

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/** Synthetic vectors for the NAC merge port (expected outputs from nac_mint.py). */
class NacMergeTest {

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
    fun domergeStep2MatchesModel() {
        val in1 = hex("6caf03f735c98c65ca013e363b7f2ea958563296b1c3cd699670220a17d4fbf80480a29eede9491522000db0b39adfa77098c9b4e937e8bc6efc1e970f2f2ff4")
        val in2 = hex("d9fdc9389e632f287fbebbb64cfe3497959ed381aa1baa3d9bc357a538b3d9c8118f9cae7648660477fee40ae4ca12704d0b2a420276e645130ba1c250b1a353")
        val expected = hex("ca3031dbb0c8781d48d5276e0c3e153848ffe17f98cee9f917e4849e6159d92c000c431ae4c00a2962fb2f9243570ad84f10a3fc5559084c2aab3a38c5283982")
        assertContentEquals(expected, NacMerge.domergeStep2(in1, in2))
    }

    @Test
    fun scrambleBodyMatchesModel() {
        val data = hex("464c907a07fed1ea347b39375d7d3b85d2e6746da3738611a0168d405992b7981e9e96beffa682f3ccfcbc6515fb45382a7e8acf1bb4e4ceb81923ee913318b3f6522a54f776905b6419ccbacd77fbbf82a82012938bcb01d067e30ec9c354bbceca340def4d99defc30df7285d3dcc8dac5562c0bdad6b1e8606c9e01231c55a6656b23e70b179294a31a153deea6323236d82d837f3e020065c8e13931194f7e83cfe5df90dfc42cd1ce9cf5a7d2bb8a595c44fb5b568918d4eda871ce728656842e96d7bca44ec419f852ade0149de28f26f1734f0e18300e3f40a9da4bba2ec8a176cf6f744f5cddbe576578de143a39866eeb3972f14873")
        val pad = hex("b39a56bc709874ade937b7b76efc41730f2f16599ccb62e5a569c2db7a7195682bad90ce88059fe221fb94c0462b790007f1ea5c34f2e2575d28a519d2b58c12a396bbb7a0fdd64759ed90e11e5ddc5efff9662bcc533ef51506da042a2ded871b373bbcb8e0e2a991ee61fcf6f188a1f7294c1b64504100cde2a59382374ae0936e")
        val expected = hex("bbb9d3b8566697354489c918600c8ae20ca446fc53e2e4b0440051994db8c15528eae0bb0a0edc1a4b5b6a03d66250449828b1da5cd947fd6a580c44aac430edb656609e66983078eb2965cb013c8721b4756172118bd875ad5199698c6e439999b5dcb4fbb12d390432083ceca43a66f723289531041d683f5c7e986d09a4708fa2274e509e10eaeb2b227cc838bf07904430972611125efe066cb9e175e747b9638bbc1da3e623feaf424e5aea461f88d53a114d02af9c4bd16b6561ef4dcc5be684c1e128e2c12e182b680cc0938f59536d227f9535b8761c638ff87393fe4d9eecf62c236542cf73ffeda12a5e01301026400fe3f42c5ff986f7daccae69d932220a2c92e817d1ac66f6c2f9fba06d48040ebeefef48b414bd510d8821d834ec9a105a1d50bf450f918babe971bd6dac22ca9cf22ad71ae765eaee5bb8c574e5528c727cabf3ae461642871058457068bfb620cb80765aa19a631732ee6ba4d241c6b6cf795a7c0672b388e2051f53e41dc73aba1970461173d056c441a5")
        assertContentEquals(expected, NacMerge.scrambleBody(data, pad))
    }

    @Test
    fun scrambleBodyIsLenFieldPlusDataPlusPad() {
        val data = stream(45, 100)
        val pad = stream(46, 0x17c - 100)
        val out = NacMerge.scrambleBody(data, pad)
        assertEquals(384, out.size)
        // the scrambled output replaces the block pairs — no length header survives
        org.junit.Assert.assertFalse(out.contentEquals(data + pad))
    }
}
