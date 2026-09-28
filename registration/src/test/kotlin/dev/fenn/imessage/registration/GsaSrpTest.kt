package dev.fenn.imessage.registration

import dev.fenn.imessage.codec.NativePlist
import dev.fenn.imessage.codec.Plist
import dev.fenn.imessage.codec.PlistDate
import dev.fenn.imessage.codec.PlistFormatException
import dev.fenn.imessage.codec.XmlPlist
import dev.fenn.imessage.codec.integerOrNull
import dev.fenn.imessage.codec.longOrNull
import dev.fenn.imessage.codec.stringKeyedDictOrNull
import dev.fenn.imessage.codec.typeName
import dev.fenn.imessage.courier.CourierClient
import dev.fenn.imessage.courier.CourierCommands
import dev.fenn.imessage.courier.CourierFrame
import dev.fenn.imessage.ids.AppleTrust
import dev.fenn.imessage.ids.Bag
import dev.fenn.imessage.ids.BagKeyMissingException
import dev.fenn.imessage.ids.IdsBagFetcher
import dev.fenn.imessage.ids.IdsHttp
import dev.fenn.imessage.ids.IdsHttpResponse
import dev.fenn.imessage.ids.IdsIdentity
import dev.fenn.imessage.ids.IdsLookupClient
import dev.fenn.imessage.ids.IdsLookupException
import dev.fenn.imessage.ids.IdsLookupResult
import dev.fenn.imessage.ids.IdsSigning
import dev.fenn.imessage.ids.TunnelReply
import dev.fenn.imessage.ids.TunnelStatus
import dev.fenn.imessage.crypto.EcCrypto
import dev.fenn.imessage.crypto.MessageBody
import dev.fenn.imessage.crypto.PairEcEnvelope
import dev.fenn.imessage.crypto.PairEnvelope
import dev.fenn.imessage.crypto.PayloadCommands
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Test-local AES-256-CBC/PKCS7 encryptor (the production side only decrypts). */
private object TestAesCbc {
    fun encrypt(plain: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(plain)
    }
}

/**
 * The §1.5 SRP-6a GSA variant, pinned two ways:
 *
 * 1. Known answers computed with an independent script straight from the spec text during
 *    development (the KAT encodes the GSA identity-hash quirk — an EMPTY username inside the
 *    identity hash — and the real username in M1's H(username) term; any deviation from the
 *    recorded derivation shifts M1/M2). Recomputed for the recorded RFC 5054 2048-bit group
 *    (C59) with the same script, re-validated first against the previous test-prime vectors.
 * 2. A scripted in-test SRP server implementing the same §1.5 formulas, so init→complete
 *    round-trips with random values and the session key K decrypts a server-encrypted `spd`.
 */
class GsaSrpTest {

    private fun fixedClient(aBytes: ByteArray) = GsaSrpClient(FixedRandom(aBytes))

    @Test
    fun `password key s2k known answer`() {
        assertEquals(
            "6b7cc6edb94620dcf9811c616742ca428fe81b5bede8478a876a895345ded185",
            GsaSrpPasswordKey.derive(PASSWORD_HASH, SALT, ITERATIONS, GsaSrpPasswordKey.PROTOCOL_S2K).toHex(),
        )
    }

    @Test
    fun `password key s2k_fo known answer - hex-encoded digest feeds pbkdf2`() {
        assertEquals(
            "5df3f8614930d6e2cf855fc8ddec13b51431c6c08e3375a1ef346686965d049e",
            GsaSrpPasswordKey.derive(PASSWORD_HASH, SALT, ITERATIONS, GsaSrpPasswordKey.PROTOCOL_S2K_FO).toHex(),
        )
    }

    @Test
    fun `unknown password protocol fails loudly`() {
        assertFailsWith<GsaSrpException> {
            GsaSrpPasswordKey.derive(PASSWORD_HASH, SALT, ITERATIONS, "s2k_foo")
        }
    }

    @Test
    fun `the recorded group is the RFC 5054 2048-bit prime with g 2`() {
        assertEquals(256, GsaSrpGroup.byteLength)
        assertEquals(BigInteger.TWO, GsaSrpGroup.generator)
        // Full-length big-endian modulus: top bit set (no leading zero byte, no short form).
        assertTrue(GsaSrpGroup.prime[0].toInt() and 0x80 != 0)
        assertEquals("ac6bdb41324a9a9b", GsaSrpGroup.prime.take(8).joinToString("") { "%02x".format(it) })
        assertEquals("9e4aff73", GsaSrpGroup.prime.takeLast(4).joinToString("") { "%02x".format(it) })
    }

    @Test
    fun `srp run known answer for both protocols`() {
        // The identity-hash quirk (§1.5: SHA-256 of empty username, ':' and the password buffer,
        // while M1 hashes the REAL username) is what these vectors were computed with.
        GSA_KAT.forEach { (protocol, kat) ->
            val client = fixedClient(FIXED_A)
            assertEquals(kat["A"], client.begin().toHex(), "A ($protocol)")
            val proof = client.proof(
                username = USERNAME.toByteArray(),
                passwordKey = GsaSrpPasswordKey.derive(PASSWORD_HASH, SALT, ITERATIONS, protocol),
                salt = SALT,
                serverPublic = FIXED_B,
            )
            assertEquals(kat["M1"], proof.m1.toHex(), "M1 ($protocol)")
            assertEquals(kat["M2"], proof.m2.toHex(), "M2 ($protocol)")
        }
    }

    @Test
    fun `a different real username shifts M1 (the H(username) term) but not A`() {
        val passwordKey = GsaSrpPasswordKey.derive(PASSWORD_HASH, SALT, ITERATIONS, GsaSrpPasswordKey.PROTOCOL_S2K)
        val a = fixedClient(FIXED_A)
        val aPublic = a.begin()
        val m1Other = a.proof(
            "someone.else@example.com".toByteArray(), passwordKey, SALT, FIXED_B,
        ).m1
        val m1Kat = GSA_KAT.getValue(GsaSrpPasswordKey.PROTOCOL_S2K).getValue("M1")
        assertTrue(!m1Other.toHex().equals(m1Kat), "M1 must depend on the real username")
        assertEquals(
            GSA_KAT.getValue(GsaSrpPasswordKey.PROTOCOL_S2K).getValue("A"),
            aPublic.toHex(),
        )
    }

    @Test
    fun `round-trips against a scripted server and decrypts its spd`() = repeat(RUNS) {
        val group = GsaSrpGroup
        val passwordKey = GsaSrpPasswordKey.derive(PASSWORD_HASH, SALT, ITERATIONS, GsaSrpPasswordKey.PROTOCOL_S2K)

        // Server side, per the same §1.5 formulas: v = g^x with the quirk identity hash.
        val serverPrivate = BigInteger(1, randomBytes(group.byteLength - 1))
        val x = BigInteger(
            1,
            sha256(SALT + sha256(byteArrayOf(':'.code.toByte()) + passwordKey)),
        )
        val verifier = group.generator.modPow(x, group.n)
        val k = BigInteger(1, sha256(group.prime + ByteArray(group.byteLength - 1) + 0x02.toByte()))
        val serverPublic = k.multiply(verifier).add(group.generator.modPow(serverPrivate, group.n)).mod(group.n)

        val client = GsaSrpClient()
        val aPublic = client.begin()
        val proof = client.proof(USERNAME.toByteArray(), passwordKey, SALT, minimalBytes(serverPublic))

        // The server verifies M1 and produces its own K from the same premaster.
        val u = BigInteger(1, sha256(aPublic + minimalBytes(serverPublic)))
        val premaster = aPublic.toBigInteger().multiply(
            verifier.modPow(u, group.n),
        ).mod(group.n).modPow(serverPrivate, group.n)
        val serverK = sha256(minimalBytes(premaster))
        val m1 = sha256(
            xor(sha256(group.prime), sha256(ByteArray(group.byteLength - 1) + 0x02.toByte())) +
                sha256(USERNAME.toByteArray()) + SALT + aPublic + minimalBytes(serverPublic) + serverK,
        )
        assertTrue(m1.contentEquals(proof.m1), "server verifies M1")
        val m2 = sha256(aPublic + m1 + serverK)
        assertTrue(m2.contentEquals(proof.m2), "client's expected M2 matches the server's")

        // The session key K decrypts a server-encrypted spd (§1.5 labels).
        val spdPlain = XmlPlist.encode(mapOf("adsid" to "an-adsid", "t" to emptyMap<String, Any?>()))
        val spdCipher = TestAesCbc.encrypt(spdPlain, GsaSpdDecryptor.key(serverK), GsaSpdDecryptor.iv(serverK))
        val decrypted = GsaSpdDecryptor.decrypt(spdCipher, proof.k)
        assertEquals("an-adsid", decrypted["adsid"])
    }

    @Test
    fun `server public value at or above N fails loudly`() {
        val group = GsaSrpGroup
        val client = fixedClient(FIXED_A)
        client.begin()
        val passwordKey = GsaSrpPasswordKey.derive(PASSWORD_HASH, SALT, ITERATIONS, GsaSrpPasswordKey.PROTOCOL_S2K)
        assertFailsWith<GsaSrpException> {
            client.proof(USERNAME.toByteArray(), passwordKey, SALT, group.prime)
        }
        assertFailsWith<GsaSrpException> {
            client.proof(USERNAME.toByteArray(), passwordKey, SALT, ByteArray(group.byteLength))
        }
    }

    @Test
    fun `proof before begin fails loudly`() {
        assertFailsWith<GsaSrpException> {
            GsaSrpClient().proof(
                USERNAME.toByteArray(),
                GsaSrpPasswordKey.derive(PASSWORD_HASH, SALT, ITERATIONS, GsaSrpPasswordKey.PROTOCOL_S2K),
                SALT,
                FIXED_B,
            )
        }
    }

    // ---- scripted server helpers (test-local implementations of the §1.5 formulas) ----

    private fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun xor(a: ByteArray, b: ByteArray): ByteArray =
        ByteArray(a.size) { (a[it].toInt() xor b[it].toInt()).toByte() }

    private fun minimalBytes(value: BigInteger): ByteArray {
        val signed = value.toByteArray()
        return if (signed.size > 1 && signed[0] == 0.toByte()) signed.copyOfRange(1, signed.size) else signed
    }

    private fun randomBytes(count: Int): ByteArray = ByteArray(count).also { SecureRandom().nextBytes(it) }

    private fun ByteArray.toBigInteger() = BigInteger(1, this)

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }

    private class FixedRandom(private val source: ByteArray) : SecureRandom() {
        override fun nextBytes(bytes: ByteArray) {
            source.copyInto(bytes, 0, 0, minOf(source.size, bytes.size))
            require(source.size >= bytes.size) { "fixed random source too short" }
        }
    }

    companion object {
        const val USERNAME = "user@example.com"
        val PASSWORD_HASH = sha256Static("correct horse battery staple".toByteArray())
        val SALT = ByteArray(16) { it.toByte() }
        const val ITERATIONS = 1000
        val FIXED_A = ByteArray(GsaSrpGroup.byteLength - 1) { 0x11.toByte() }
        val FIXED_B = ByteArray(GsaSrpGroup.byteLength) { 0x21.toByte() }
        const val RUNS = 8

        /** KATs from the independent dev script (values only — nothing copied from any source). */
        val GSA_KAT = mapOf(
            GsaSrpPasswordKey.PROTOCOL_S2K to mapOf(
                "A" to "2ef21a178863a757ceb9c9e542e3f6e015500ebcde624d0945a9b6497844f2dc2a1ea26e8914ec725bdcec39d578e28da273c2a1c0a448f655f3e0e2f68056df51f3124ff949ee86586e729f7a379ae1099183509fd53c6116ac12b7da2f2ea076ce6d179f0792068ceea98059caec903e4a797b4950337834af9c94f067cdd74014d75406e01ac5beae49bba88f550b63f677bb7c5ea2c5de82881eb4e6be58ee765d24f8acdb359d130f4f1a25728476cc979672216e4ee038d395d7958d6d3f0cdcf5541d33d195744b3fe5b064e8c3c86ea93190e089239d0f4052efdac2375933440187f91a1e4bf3442b029f0d3361b3779102afc76f827560c88ac3f2",
                "M1" to "7ade59813b9b44e530c79aca6a1818ec407d3a678f40f3c4ed96873c420469bc",
                "M2" to "cb2e2fbb28040c4b2775952e11428ef7407ae310a7211c6ad590f8c975f3d9b4",
            ),
            GsaSrpPasswordKey.PROTOCOL_S2K_FO to mapOf(
                "A" to "2ef21a178863a757ceb9c9e542e3f6e015500ebcde624d0945a9b6497844f2dc2a1ea26e8914ec725bdcec39d578e28da273c2a1c0a448f655f3e0e2f68056df51f3124ff949ee86586e729f7a379ae1099183509fd53c6116ac12b7da2f2ea076ce6d179f0792068ceea98059caec903e4a797b4950337834af9c94f067cdd74014d75406e01ac5beae49bba88f550b63f677bb7c5ea2c5de82881eb4e6be58ee765d24f8acdb359d130f4f1a25728476cc979672216e4ee038d395d7958d6d3f0cdcf5541d33d195744b3fe5b064e8c3c86ea93190e089239d0f4052efdac2375933440187f91a1e4bf3442b029f0d3361b3779102afc76f827560c88ac3f2",
                "M1" to "be0d7ab2fbc3c74e8e4a59c0cb962e6cfd5c332f3d347e68f1153b2ecfdd48ba",
                "M2" to "08859fbf824b58270e4be07007e2690491e0452db3c08fc0e6e8052274455466",
            ),
        )

        private fun sha256Static(bytes: ByteArray): ByteArray =
            MessageDigest.getInstance("SHA-256").digest(bytes)
    }
}
