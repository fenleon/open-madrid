package dev.fenn.imessage.registration

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/** Synthetic vectors for the NAC stamp assembly (expected outputs from nac_mint.py). */
class NacValidationTest {

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
    fun mintMatchesModel() {
        val cert = hex("20e91cfed93217709ef434387f7b48614c77b74495233fb9aabcf7769b50733838bc8ade1164bbd176f96c1b775bacc8e4634bea4d30e1e0023727451338017250da4c1b49841d344ec155086f42bd")
        val session = hex("8d37e33f42cdb93253b1b2b890fa4e4f89bf58308e7b1b8daf0f2d12bc2f510845cb84ee9ac2d7c0cbf74476a88bdf90c1d6ab77666edf69a745a97054ba75d1fd1dde7ef20a642043951a2fc0279e9cf99cf35d3ee423dc9f42c7f0ecff1d21b50f481a4a067640bb69670fd82ee15231f236f9163d169d97e6187e8460a6f66d8057e0a214b12f3355fb59f0006bbc69b6787deed82ff28f118ce81c3c979425505df2fa95c401ab37c21f08fee92ba1c93780c617b66a87a3ea93b4f2243add5ee66e52eaebe423f143672086780fd90bef2b9e593acd7f7c5a974ce4af8c958c3b5daa716e679b6124c438f91c72115d956376fe1935777c")
        val pad = hex("b39a56bc709874ade937b7b76efc41730f2f16599ccb62e5a569c2db7a7195682bad90ce88059fe221fb94c0462b790007f1ea5c34f2e2575d28a519d2b58c12a396bbb7a0fdd64759ed90e11e5ddc5efff9662bcc533ef51506da042a2ded871b373bbcb8e0e2a991ee61fcf6f188a1f7294c1b64504100cde2a59382374ae0936e")
        val rand = hex("fa85a981ab675cf5086e3039a179553d")
        val sig = hex("67d46fc31402ffb7bd2aaeb9b2f85b2b")
        val expected = hex("02fa85a981ab675cf5086e3039a179553d67d46fc31402ffb7bd2aaeb9b2f85b2b000001e00500000001000001806c0bf5acdd4b1a845bfc27ddf00268755345d86747bb2f7aed33ef8337683b17e8ba131f2f30d283d164ce71833254883d8647c50e1c062be8c3f50d600fbbf2944fd70422b3187abe569be9ca1f2961ca8b1e1529567c4761138b33aab563e92ca156efcb5a23339e3eadba6d23be8e753ccbd26a1bc288dfe54bd250843fd5dfd8df60e1133f29bab2eaefbde9d742da34f69b38ab5d4909bbc15baa4384b71168acf3f4b518581515ad82386d4b3a9f5ee5a54721d1524325e3aeb6fef198911f05b84eff5efc924ddc96a59333e935f507ac68f53bc61d04e952f6b58c5a090963c8fb399f467be8cd8914e01e29e36fc4c4451ff30681aa36e28960c734d932220a2c92e817d1ac66f6c2f9fba06d48040ebeefef48b414bd510d8821d834ec9a105a1d50bf450f918babe971bd6dac22ca9cf22ad71ae765eaee5bb8c574e5528c727cabf3ae461642871058457068bfb620cb80765aa19a631732ee6ba4d241c6b6cf795a7c0672b388e2051f53e41dc73aba1970461173d056c441a5000000000000004f20e91cfed93217709ef434387f7b48614c77b74495233fb9aabcf7769b50733838bc8ade1164bbd176f96c1b775bacc8e4634bea4d30e1e0023727451338017250da4c1b49841d344ec155086f42bd")
        assertContentEquals(expected, NacValidation.mint(cert, session, pad, rand, sig))
    }

    @Test
    fun mintStampLayout() {
        val cert = stream(51, 79)
        val session = stream(52, 250)
        val pad = stream(53, 130)
        val rand = stream(54, 16)
        val sig = stream(55, 16)
        val stamp = NacValidation.mint(cert, session, pad, rand, sig)
        assertEquals(517, stamp.size)
        assertEquals(2, stamp[0].toInt() and 0xff)
        assertContentEquals(rand, stamp.copyOfRange(1, 17))
        assertContentEquals(sig, stamp.copyOfRange(17, 33))
        assertEquals(480, ((stamp[33].toInt() and 0xff) shl 24) or
            ((stamp[34].toInt() and 0xff) shl 16) or
            ((stamp[35].toInt() and 0xff) shl 8) or (stamp[36].toInt() and 0xff))
        assertEquals(5, stamp[37].toInt() and 0xff)
        assertEquals(79, ((stamp[434].toInt() and 0xff) shl 24) or
            ((stamp[435].toInt() and 0xff) shl 16) or
            ((stamp[436].toInt() and 0xff) shl 8) or (stamp[437].toInt() and 0xff))
        assertContentEquals(cert, stamp.copyOfRange(438, 517))
    }

    @Test
    fun keyEstablishmentMatchesModel() {
        val pearKey = hex("aebfc2884fd1e6ffdc60273be5756ff5")
        val sessionInfo = hex("021b0e89cab86b89c2911da5bbf6f475e3000002502feb2054e4786cfb482f083fb085cb87e0906991e2003bb2a45b65ecf9764d2c39bafe46cdd93600af6d1af6f27999fb275eacc6b6663b075be0bee9fc04e4018899a0e028954cd0f74a51d3c353a1b711ec431974926847dc715d71918f43d424a0c8ea663034699e704306c3c25ab7fa76e3e99a8944a6c1916204bb923e41218232ccc2d4df2658f96bad8f1e4e8e41c20a159de8485e1ec398ea86d1ef9f036d3c92d103500f9be66718c503c18d6cf724909a7e29da398a6b360b56511c034a437483612b5ee1f1fcdb582e0e9a6de81e306542beac6e96c89faa1eb43324b7051598bac4c7e2542542a0bfd6704152a187fe61623b0fdd9ec67105b22190c4b06b68c66a1ddd972ef6e23b269e128a21d9f36c0f0ca1422f4ea90bb1b7e6c5f32d524bd38beaffe99af5ad573fe7a07f3f20094adb6aa281b95e3a20fd6b7489c8d231d94287165e425de90ce4bf0a21cf523146fb0e1dac3c942eb40f75db11b3edd853975f37851adcb8883eac8952d8ad8232d17910ffcd8524167d7c14034b19e3c4a28266d45569384c5d2591333b46a542981ef4ed16e57979170276e079efecf83ec517b12ffa8cf6968d0d7ffb4c15422a6ca034d93096311bfdb724ea37155a2b8923d2bd8eb270b378f528ffd694c0a822bfe1c3016853c6474bada51f519e440f68df4589b377e36f19f839b8fa4965836d75135a5fc7dde8e083652a692cf0e2236e23044e20703d46ac3535ad2e084289c94c4e46c2220fd53e72d5ecba1baab23063544b03c01fb37160e2f2b7878ca58e55944f879c8e5a3feb6ae035cd16a4ec555c28fd73f5aa154e8aa0ce47fb96a0bc18f382bf7101638d563bfe2bd7a7d7ebc4284087ad43556ee2b6ba3973ea044d300d79d2a96dafe22e5fd1b1cfbab9cc5ccc19cd653b689b3a409882eb3441654852a593e128262806")
        val expected = hex("b935834c7d6a709f3b276fc3e0e4fc7dc5206bc6dc1bed36fbc50a49a227a2bfd6e413e93c47343eb0bd86f1870d10a67d162e3bd45536193adfb75fd939b26d2a3bceda6b3393f9a3d21616cc4a47e8001fad359a6121ed07c18bfc0910ded04311daec6c3c0419a1636eb0e49b5bd8c66705d1edc6f30b4b4e611dc1347496e221b42fbc13d7363be6b994dba12a30d43e0d3b80123a4802276ac368fdba5128916b9cf2db773adc86dd2d3f07b1698c53da2216d73c0da7084a94066b9c3be8e90f92da6af7ceaa4ed315649ed37d47d6b7c198e6214660b120a3bb7b63f6656f5757e9990dd298d6411be077d6a5b132acb9a2da3fe43c9fafe9b099d6f2ae6e21f6250938e83f86544f750df1f248c289d8598970edee01304890d3adeb15bda82e36ac4f36e64fd9e950b38018b8c659072754c9b5baef91445e04afa3fbc72123a6d78ca16b5aad184555fe01682fa456adc699fd88a88fedd779680c076e9f88d72ff307e2a2ad6fc1f5b25fb8d3fdf0b73db3bce19e2a329fff7ee248ae1d30b823197ad2793b17e6db7652cc29206131ba382102a92d32bdd8c3ebdf2de8c040cd0ca24870409be2d301ed8aadb35303dd21efdc30c3168c0bc887a05824aa6e16ba5cf8cc75a93c54945b9e758c4813f54bc4d5c4654cc9fdc6843114af607ec22e8cb9d9b97ab33c8ca5cc9230c96dee22a242aab0ec8bd83e1fad1dd4f4e42d550a95f0daa08708465c6f1ead67ff046c9df1a14f35cf8ccf1078ec246226f4fdc34c8fc6c32a21d8a211bc489e5cd735074f838d917617399ccfb60a8e7d4db3dc1de397bba7aacd66")
        val pt = NacValidation.keyEstablishment(sessionInfo, pearKey)
        assertContentEquals(expected, pt)
        assertEquals(592, pt.size)
    }
}
