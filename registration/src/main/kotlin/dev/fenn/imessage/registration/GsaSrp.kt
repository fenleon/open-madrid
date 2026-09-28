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
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** SRP math or password-key derivation failure (spec §1.5). */
class GsaSrpException(message: String) : Exception(message)

/**
 * The recorded SRP group of the GSA login chain (spec §1.5, C59): the RFC 5054 2048-bit MODP
 * group — the standard Appendix-A prime — with g = 2, as 256 big-endian modulus bytes hashed
 * verbatim in the k/M1 derivations.
 */
object GsaSrpGroup {

    /** RFC 5054 Appendix A, 2048-bit group (the standard Appendix-A prime, spec §1.5). */
    private const val PRIME_HEX =
        "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
            "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50" +
            "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8" +
            "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B" +
            "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748" +
            "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6" +
            "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
            "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"

    val generator: BigInteger = BigInteger.TWO

    /** The modulus as big-endian bytes — hashed verbatim in the k/M1 derivations (§1.5). */
    val prime: ByteArray = PRIME_HEX.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    val n: BigInteger = BigInteger(1, prime)

    val byteLength: Int = prime.size
}

/**
 * The password-key derivation of spec §1.5 ("s2k" vs "s2k_fo"): SHA-256 of the raw password,
 * then — for `s2k_fo` — that digest ASCII-lowercase-hex-encoded (64 chars) is what feeds
 * PBKDF2, for `s2k` the raw 32-byte digest feeds it; PBKDF2-HMAC-SHA256 over the server salt
 * with the server iteration count, 32 output bytes.
 *
 * The input here is the SHA-256 of the raw password (§1.5's derivation start — and exactly the
 * "persisted password hash" the silent re-login reuses, §1.5 PET), so nothing is re-hashed
 * here. PBKDF2 is hand-rolled over HmacSHA256 because the input is raw bytes,
 * not chars (JCE's char[]-based PBE would re-encode them).
 */
object GsaSrpPasswordKey {

    const val PROTOCOL_S2K = "s2k"
    const val PROTOCOL_S2K_FO = "s2k_fo"

    /** The `ps` array of the init request (§1.5) — both protocols offered. */
    val OFFERED_PROTOCOLS = listOf(PROTOCOL_S2K, PROTOCOL_S2K_FO)

    fun derive(passwordDigest: ByteArray, salt: ByteArray, iterations: Int, protocol: String): ByteArray {
        require(iterations > 0) { "SRP iteration count must be positive, got $iterations" }
        val pbkdf2Input = when (protocol) {
            PROTOCOL_S2K -> passwordDigest
            PROTOCOL_S2K_FO -> passwordDigest.joinToString("") { byte -> "%02x".format(byte) }
                .toByteArray(Charsets.US_ASCII)
            else -> throw GsaSrpException(
                "unrecognized SRP password protocol '$protocol' (expected $PROTOCOL_S2K or $PROTOCOL_S2K_FO)",
            )
        }
        return pbkdf2HmacSha256(pbkdf2Input, salt, iterations, 32)
    }

    /** RFC 2898 PBKDF2 with HMAC-SHA256, [dkLen]-byte output. */
    private fun pbkdf2HmacSha256(password: ByteArray, salt: ByteArray, iterations: Int, dkLen: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(password, "HmacSHA256"))
        val blocks = (dkLen + mac.macLength - 1) / mac.macLength
        val out = ByteArray(blocks * mac.macLength)
        for (block in 1..blocks) {
            mac.update(salt)
            mac.update(intToBigEndian(block))
            var u = mac.doFinal()
            val t = u.copyOf()
            for (round in 2..iterations) {
                u = mac.doFinal(u)
                for (i in t.indices) t[i] = (t[i].toInt() xor u[i].toInt()).toByte()
            }
            System.arraycopy(t, 0, out, (block - 1) * mac.macLength, mac.macLength)
        }
        return out.copyOf(dkLen)
    }

    private fun intToBigEndian(value: Int): ByteArray = byteArrayOf(
        (value ushr 24).toByte(),
        (value ushr 16).toByte(),
        (value ushr 8).toByte(),
        value.toByte(),
    )
}

/** One complete SRP client run: the M1 proof to send, the M2 to expect, and the session key K. */
class SrpProof(
    /** The client proof to send as the complete request's `M1` (§1.5). */
    val m1: ByteArray,
    /** The server proof to expect in the complete response's `M2` (§1.5). */
    val m2: ByteArray,
    /** The session key K — decrypts the complete response's `spd` (§1.5). Never logged. */
    internal val k: ByteArray,
)

/**
 * The GSA SRP-6a client of spec §1.5, byte-exact: the RFC 5054 2048-bit group with g = 2
 * ([GsaSrpGroup]), SHA-256 throughout, and the GSA identity-hash quirk — the identity
 * hash is SHA-256 over an EMPTY username, ":" and the password buffer, while M1's H(username)
 * term uses the REAL username.
 *
 * Wire-encoding notes, from the §1.5 formulas: `pad` appears only in the k derivation (g
 * left-padded to N's length) and in M1's H(pad(g)) term — every other hashed byte string (A,
 * B, salt, K, premaster) enters as the minimal big-endian / as-received form. A is sent as
 * `A2k` in exactly the minimal form hashed here; B is hashed exactly as received.
 */
class GsaSrpClient(private val random: SecureRandom = SecureRandom()) {

    private val group = GsaSrpGroup

    private var privateA: BigInteger? = null
    private var publicA: ByteArray? = null

    /**
     * Generates the ephemeral private value and computes A = g^a mod N. Returns A as the
     * minimal big-endian bytes sent as `A2k`. A 255-byte private value is always < N for any
     * 2048-bit prime (top bit set), so no rejection sampling is needed.
     */
    fun begin(): ByteArray {
        val aBytes = ByteArray(group.byteLength - 1)
        random.nextBytes(aBytes)
        val a = BigInteger(1, aBytes)
        require(a.signum() > 0) { "SRP private value must not be zero" }
        privateA = a
        publicA = minimalBytes(group.generator.modPow(a, group.n))
        return publicA!!.copyOf()
    }

    /**
     * Computes the proofs from the server's init response. [username] is the REAL username
     * (M1's H(username) term); the identity-hash quirk applies inside. [passwordKey] is the
     * §1.5 derivation output ([GsaSrpPasswordKey.derive]); [salt] and [serverPublic] are the
     * init response's `s` and `B` verbatim.
     */
    fun proof(
        username: ByteArray,
        passwordKey: ByteArray,
        salt: ByteArray,
        serverPublic: ByteArray,
    ): SrpProof {
        val a = privateA ?: throw GsaSrpException("begin() must run before proof()")
        val aBytes = publicA!!
        val b = BigInteger(1, serverPublic)
        if (b >= group.n) throw GsaSrpException("server public value B is not in [0, N)")
        if (b.signum() == 0) throw GsaSrpException("server public value B is zero")

        // GSA quirk (§1.5): EMPTY username in the identity hash — H(":" ‖ password buffer).
        val identityHash = sha256(byteArrayOf(':'.code.toByte()) + passwordKey)
        val x = BigInteger(1, sha256(salt + identityHash))
        val u = BigInteger(1, sha256(aBytes + serverPublic))
        val k = BigInteger(1, sha256(group.prime + padLeft(group.generator.toByteArray(), group.byteLength)))

        val base = b.subtract(k.multiply(group.generator.modPow(x, group.n))).mod(group.n)
        val premaster = base.modPow(a.add(u.multiply(x)), group.n)
        val sessionK = sha256(minimalBytes(premaster))

        val m1 = sha256(
            xor(sha256(group.prime), sha256(padLeft(group.generator.toByteArray(), group.byteLength))) +
                sha256(username) + salt + aBytes + serverPublic + sessionK,
        )
        val m2 = sha256(aBytes + m1 + sessionK)
        return SrpProof(m1 = m1, m2 = m2, k = sessionK)
    }

    private fun padLeft(bytes: ByteArray, length: Int): ByteArray {
        require(bytes.size <= length) { "value longer than the group modulus" }
        if (bytes.size == length) return bytes
        // BigInteger.toByteArray may carry a leading sign byte — drop it before padding.
        val unsigned = if (bytes.isNotEmpty() && bytes[0] == 0.toByte() && bytes.size - 1 <= length) {
            bytes.copyOfRange(1, bytes.size)
        } else {
            bytes
        }
        return ByteArray(length - unsigned.size) + unsigned
    }

    private fun minimalBytes(value: BigInteger): ByteArray {
        val signed = value.toByteArray()
        return if (signed.size > 1 && signed[0] == 0.toByte()) signed.copyOfRange(1, signed.size) else signed
    }

    private fun xor(a: ByteArray, b: ByteArray): ByteArray {
        require(a.size == b.size) { "XOR operands differ in length" }
        return ByteArray(a.size) { (a[it].toInt() xor b[it].toInt()).toByte() }
    }

    private fun sha256(bytes: ByteArray): ByteArray =
        java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
}
