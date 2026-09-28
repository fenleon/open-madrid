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
import java.security.KeyPair
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.util.Base64

/**
 * Case of the hex encoding of the authenticate CSR's common name — the SHA-1 digest of the
 * realm user id is a hex STRING (not raw, not base64, §1.2). Case is a C57 disagreement:
 * one source uppercases, the other lowercases. Default [UPPER] matches the section's prose,
 * which reads the uppercase variant first.
 */
enum class HexCase { UPPER, LOWER }

/**
 * The hash a CSR's self-signature uses. On the authenticate CSR this is a C57 disagreement
 * (§1.2: SHA-1 RSA/PKCS1 vs SHA256WithRSA) — a parameter with the SHA-1 default. The Albert
 * push CSR's hash is recorded outright (SHA-1WithRSA, §1.2) and does not ride this choice.
 */
enum class CsrSignatureHash(val javaAlgorithm: String, val oid: String) {
    SHA1("SHA1withRSA", "1.2.840.113549.1.1.5"),
    SHA256("SHA256withRSA", "1.2.840.113549.1.1.11"),
}

/** PEM armor (§1.2: the `DeviceCertRequest` is a PEM CSR; the Albert `DeviceCertificate` returns as PEM). */
object Pem {
    const val CSR_TYPE = "CERTIFICATE REQUEST"
    const val CERTIFICATE_TYPE = "CERTIFICATE"

    fun encode(type: String, der: ByteArray): String {
        val lines = Base64.getEncoder().encodeToString(der).chunked(64).joinToString("\n")
        return "-----BEGIN $type-----\n$lines\n-----END $type-----\n"
    }

    fun decode(pem: String, type: String): ByteArray {
        val begin = "-----BEGIN $type-----"
        val end = "-----END $type-----"
        val start = pem.indexOf(begin)
        require(start >= 0) { "no $begin block found" }
        val stop = pem.indexOf(end, start + begin.length)
        require(stop > start) { "unterminated $begin block" }
        val body = pem.substring(start + begin.length, stop).filterNot { it.isWhitespace() }
        return Base64.getDecoder().decode(body)
    }
}

/** A PKCS#10 certification request: DER bytes and their PEM armor (§1.2 "CSR", DER on the wire). */
class IdsCsr(val der: ByteArray, val pem: String)

/**
 * Minimal DER writer + PKCS#10 builder. The JDK has no public PKCS#10 API, so the request is
 * hand-encoded: CertificationRequest ::= SEQUENCE { CertificationRequestInfo, signature
 * AlgorithmIdentifier, signature BIT STRING }, with the request info carrying version 0, the
 * subject RDN sequence, the RSA SubjectPublicKeyInfo, and empty [0] attributes.
 */
object IdsCsrBuilder {

    /**
     * The authenticate CSR's common name: the hex SHA-1 of the realm user id (§1.2). Phone
     * realm user ids have the "P:<number>" form. Hex case rides C57 — see [HexCase].
     */
    fun realmUserIdCn(realmUserId: String, hexCase: HexCase = HexCase.UPPER): String {
        val digest = MessageDigest.getInstance("SHA-1").digest(realmUserId.toByteArray(Charsets.UTF_8))
        val hex = digest.joinToString("") { "%02x".format(it) }
        return if (hexCase == HexCase.UPPER) hex.uppercase() else hex
    }

    /**
     * Builds and self-signs a CSR with [keyPair]'s private key. [selfSignatureHash] is the C57
     * parameter (§1.2) — note the Android Keystore spec in [IdsKeys] currently provisions
     * SHA-1 digests only, so SHA-256 needs a keystore-spec change before it works there.
     */
    fun create(
        keyPair: KeyPair,
        commonName: String,
        organizationalUnit: String? = null,
        organization: String? = null,
        selfSignatureHash: CsrSignatureHash = CsrSignatureHash.SHA1,
    ): IdsCsr {
        val public = keyPair.public as? RSAPublicKey
            ?: throw IllegalArgumentException("CSR key must be RSA, was ${keyPair.public.algorithm}")
        val rdns = buildList {
            add(Der.setOf(nameEntry(OID_COMMON_NAME, commonName)))
            organizationalUnit?.let { add(Der.setOf(nameEntry(OID_ORGANIZATIONAL_UNIT, it))) }
            organization?.let { add(Der.setOf(nameEntry(OID_ORGANIZATION, it))) }
        }
        val publicKeyInfo = Der.sequence(
            Der.sequence(Der.oid(OID_RSA_ENCRYPTION), Der.nullValue()),
            Der.bitString(
                Der.sequence(Der.integer(public.modulus), Der.integer(public.publicExponent)),
            ),
        )
        val requestInfo = Der.sequence(
            Der.integer(BigInteger.ZERO),
            Der.sequence(*rdns.toTypedArray()),
            publicKeyInfo,
            Der.contextConstructed(0),
        )
        val signer = Signature.getInstance(selfSignatureHash.javaAlgorithm)
        signer.initSign(keyPair.private)
        signer.update(requestInfo)
        val der = Der.sequence(
            requestInfo,
            Der.sequence(Der.oid(selfSignatureHash.oid), Der.nullValue()),
            Der.bitString(signer.sign()),
        )
        return IdsCsr(der, Pem.encode(Pem.CSR_TYPE, der))
    }

    private fun nameEntry(oid: String, value: String): ByteArray =
        Der.sequence(Der.oid(oid), Der.utf8String(value))

    private const val OID_COMMON_NAME = "2.5.4.3"
    private const val OID_ORGANIZATIONAL_UNIT = "2.5.4.11"
    private const val OID_ORGANIZATION = "2.5.4.10"
    private const val OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
}

internal object Der {

    fun sequence(vararg parts: ByteArray): ByteArray = tagged(0x30, concat(parts))
    fun setOf(vararg parts: ByteArray): ByteArray = tagged(0x31, concat(parts))
    fun integer(value: BigInteger): ByteArray = tagged(0x02, value.toByteArray())
    fun utf8String(value: String): ByteArray = tagged(0x0c, value.toByteArray(Charsets.UTF_8))
    fun octetString(value: ByteArray): ByteArray = tagged(0x04, value)
    fun bitString(value: ByteArray): ByteArray = tagged(0x03, byteArrayOf(0) + value)
    fun nullValue(): ByteArray = byteArrayOf(0x05, 0x00)
    fun contextConstructed(tag: Int, body: ByteArray = ByteArray(0)): ByteArray = tagged(0xa0 or tag, body)

    fun oid(dotted: String): ByteArray {
        val arcs = dotted.split('.').map { it.toLong() }
        require(arcs.size >= 2) { "OID needs at least two arcs: $dotted" }
        require(arcs[0] in 0..2 && arcs[1] >= 0) { "OID first arcs out of range: $dotted" }
        val body = ArrayList<Byte>()
        body.add((arcs[0] * 40 + arcs[1]).toByte())
        for (arc in arcs.drop(2)) {
            require(arc >= 0) { "negative OID arc: $dotted" }
            // little-endian base-128 (continuation bit high), reversed to wire order below
            val group = ArrayList<Byte>()
            var v = arc
            group.add((v and 0x7f).toByte())
            v = v ushr 7
            while (v != 0L) {
                group.add(((v and 0x7f).toInt() or 0x80).toByte())
                v = v ushr 7
            }
            group.reverse()
            body.addAll(group)
        }
        return tagged(0x06, body.toByteArray())
    }

    private fun concat(parts: Array<out ByteArray>): ByteArray {
        val size = parts.sumOf { it.size }
        val out = ByteArray(size)
        var at = 0
        for (part in parts) {
            part.copyInto(out, at)
            at += part.size
        }
        return out
    }

    private fun tagged(tag: Int, body: ByteArray): ByteArray {
        val header = ArrayList<Byte>(5)
        header.add(tag.toByte())
        when {
            body.size < 0x80 -> header.add(body.size.toByte())
            body.size < 0x100 -> {
                header.add(0x81.toByte())
                header.add(body.size.toByte())
            }
            body.size < 0x10000 -> {
                header.add(0x82.toByte())
                header.add((body.size ushr 8).toByte())
                header.add(body.size.toByte())
            }
            else -> throw IllegalArgumentException("DER body too long: ${body.size}")
        }
        return header.toByteArray() + body
    }
}
