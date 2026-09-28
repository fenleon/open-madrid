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
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec

/**
 * The bundled FairPlay identity of spec §1.2 (rev 17; §7 item 21 user decision): the staged
 * classpath resources `imessage/fairplay/leaf.crt` (DER leaf certificate) and
 * `imessage/fairplay/identity.key` (PEM PKCS#1 `RSA PRIVATE KEY`). `FairPlaySignature` is
 * SHA-1 RSA PKCS#1v15 over the exact serialized ActivationInfoXML bytes; `FairPlayCertChain`
 * is the DER leaf alone, passed through verbatim (§1.2 — Apple's server fills in the rest).
 *
 * The default [FairPlaySigner] of [AlbertActivator]; tests inject a scripted signer instead.
 * Only status text reaches [logEvent] — no key or certificate material ever does.
 */
class BundledFairPlaySigner(
    private val logEvent: (String) -> Unit = {},
) : FairPlaySigner {

    private val leafChain: ByteArray by lazy { resource(LEAF_CERT_RESOURCE) }

    private val identityKey: RSAPrivateKey by lazy { loadPrivateKey() }

    override fun sign(activationInfoPlist: ByteArray): FairPlayMaterial {
        logEvent("fairplay: signing the activation-info plist with the bundled identity")
        val signer = Signature.getInstance(SIGNATURE_ALGORITHM)
        signer.initSign(identityKey)
        signer.update(activationInfoPlist)
        return FairPlayMaterial(leafChain, signer.sign())
    }

    /** The DER leaf's public key — the identity the signature must verify against (§1.2). */
    fun certificatePublicKey(): RSAPublicKey = certificatePublicKey(leafChain)

    /**
     * SHA-256 of the private key's RSA modulus — the only form in which the identity key is
     * comparable from outside (validation tests pair it against the leaf certificate's key).
     */
    fun identityModulusSha256(): String = modulusSha256(identityKey.modulus)

    /**
     * The staged key is PKCS#1 PEM; the JCE wants PKCS#8. The PKCS#1 body is wrapped verbatim
     * into a minimal PKCS#8 envelope with the existing DER writer ([Der]) — never parsed,
     * never re-encoded beyond the envelope.
     */
    private fun loadPrivateKey(): RSAPrivateKey {
        val pkcs1 = Pem.decode(resource(IDENTITY_KEY_RESOURCE).decodeToString(), PKCS1_TYPE)
        val pkcs8 = Der.sequence(
            Der.integer(BigInteger.ZERO),
            Der.sequence(Der.oid(OID_RSA_ENCRYPTION), Der.nullValue()),
            Der.octetString(pkcs1),
        )
        val key = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(pkcs8))
        return key as? RSAPrivateKey
            ?: throw IllegalStateException("bundled FairPlay identity key is ${key.algorithm}, expected RSA")
    }

    private fun resource(name: String): ByteArray =
        javaClass.getResourceAsStream(name)?.use { it.readBytes() }
            ?: throw IllegalStateException("bundled FairPlay resource missing from the classpath: $name")

    companion object {
        const val LEAF_CERT_RESOURCE = "/imessage/fairplay/leaf.crt"
        const val IDENTITY_KEY_RESOURCE = "/imessage/fairplay/identity.key"

        /** §1.2: the FairPlay signature is SHA-1 RSA PKCS#1v15. */
        const val SIGNATURE_ALGORITHM = "SHA1withRSA"

        const val PKCS1_TYPE = "RSA PRIVATE KEY"

        private const val OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"

        /** Parses a DER certificate chain blob into its RSA public key. */
        fun certificatePublicKey(derChain: ByteArray): RSAPublicKey {
            val certificate = CertificateFactory.getInstance("X.509")
                .generateCertificate(derChain.inputStream())
            return certificate.publicKey as? RSAPublicKey
                ?: throw IllegalStateException(
                    "FairPlay leaf certificate key is ${certificate.publicKey.algorithm}, expected RSA",
                )
        }

        /** SHA-256 of a key modulus, hex — the identity-comparison form (never the raw bytes). */
        fun modulusSha256(modulus: BigInteger): String =
            MessageDigest.getInstance("SHA-256").digest(modulus.toByteArray())
                .joinToString("") { "%02x".format(it) }
    }
}
