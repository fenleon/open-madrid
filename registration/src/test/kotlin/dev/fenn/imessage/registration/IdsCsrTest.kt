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
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Minimal DER walk for structural CSR assertions (tag, total start, body start, body end). */
internal data class Tlv(val tag: Int, val start: Int, val bodyStart: Int, val bodyEnd: Int)

internal fun readTlv(der: ByteArray, at: Int): Tlv {
    val tag = der[at].toInt() and 0xff
    var length = der[at + 1].toInt() and 0xff
    var bodyStart = at + 2
    if (length and 0x80 != 0) {
        val byteCount = length and 0x7f
        length = 0
        repeat(byteCount) {
            length = (length shl 8) or (der[bodyStart].toInt() and 0xff)
            bodyStart++
        }
    }
    return Tlv(tag, at, bodyStart, bodyStart + length)
}

internal fun derChildren(der: ByteArray, tlv: Tlv): List<Tlv> {
    val out = ArrayList<Tlv>()
    var at = tlv.bodyStart
    while (at < tlv.bodyEnd) {
        val child = readTlv(der, at)
        out.add(child)
        at = child.bodyEnd
    }
    return out
}

internal fun derFullBytes(der: ByteArray, tlv: Tlv): ByteArray = der.copyOfRange(tlv.start, tlv.bodyEnd)

/** The CSR's subject attribute values (the UTF8 strings of the RDN sequence). */
internal fun csrSubjectValues(csrDer: ByteArray): List<String> {
    val requestInfo = derChildren(csrDer, readTlv(csrDer, 0)).first()
    val subject = derChildren(csrDer, requestInfo)[1]
    return derChildren(csrDer, subject).flatMap { set ->
        derChildren(csrDer, set).flatMap { rdn ->
            derChildren(csrDer, rdn).filter { it.tag == 0x0c }
                .map { String(csrDer, it.bodyStart, it.bodyEnd - it.bodyStart, Charsets.UTF_8) }
        }
    }
}

class IdsCsrTest {

    @Test
    fun realmUserIdCnIsTheHexSha1OfTheRealmUserId() {
        // Known answer: SHA-1("P:+15551234567") = df88e39c…f6fd7 (spec §1.2).
        assertEquals(
            "DF88E39CA8B5CFDFD8DA5D9B927D0535374F6FD7",
            IdsCsrBuilder.realmUserIdCn("P:+15551234567"),
        )
    }

    @Test
    fun realmUserIdCnHexCaseIsTheC57Parameter() {
        val lower = IdsCsrBuilder.realmUserIdCn("P:+15551234567", HexCase.LOWER)
        assertEquals("df88e39ca8b5cfdfd8da5d9b927d0535374f6fd7", lower)
        val upper = IdsCsrBuilder.realmUserIdCn("P:+15551234567", HexCase.UPPER)
        assertEquals(upper, upper.uppercase())
    }

    @Test
    fun csrSelfSignatureVerifiesOverTheRequestInfo() {
        val csr = IdsCsrBuilder.create(KEY, "test-cn", "test-ou", "test-o")

        val top = derChildren(csr.der, readTlv(csr.der, 0))
        assertEquals(3, top.size, "CertificationRequest must hold requestInfo, algId, signature")
        assertEquals(0x30, top[0].tag)
        assertEquals(0x30, top[1].tag)
        assertEquals(0x03, top[2].tag, "signature must be a BIT STRING")

        // The self-signature covers the exact requestInfo TLV bytes (§1.2, C57 parameter).
        val verifier = Signature.getInstance("SHA1withRSA")
        verifier.initVerify(KEY.public)
        verifier.update(derFullBytes(csr.der, top[0]))
        val signature = csr.der.copyOfRange(top[2].bodyStart + 1, top[2].bodyEnd)
        assertTrue(verifier.verify(signature), "CSR self-signature does not verify")

        // Default is the Rust reading of the C57 disagreement: SHA-1 with RSA/PKCS1 (§1.2).
        val algorithm = derChildren(csr.der, top[1]).first()
        assertEquals(0x06, algorithm.tag)
        assertContentEquals(Der.oid(CsrSignatureHash.SHA1.oid), csr.der.copyOfRange(algorithm.start, algorithm.bodyEnd))
    }

    @Test
    fun sha256SelfSignatureVariantVerifies() {
        val csr = IdsCsrBuilder.create(KEY, "test-cn", selfSignatureHash = CsrSignatureHash.SHA256)
        val top = derChildren(csr.der, readTlv(csr.der, 0))
        val verifier = Signature.getInstance("SHA256withRSA")
        verifier.initVerify(KEY.public)
        verifier.update(derFullBytes(csr.der, top[0]))
        assertTrue(verifier.verify(csr.der.copyOfRange(top[2].bodyStart + 1, top[2].bodyEnd)))
    }

    @Test
    fun csrCarriesTheSubjectPublicKeyAndSubject() {
        val csr = IdsCsrBuilder.create(KEY, "Client Push Certificate", "iPhone", "Apple Inc.")
        assertEquals(
            listOf("Client Push Certificate", "iPhone", "Apple Inc."),
            csrSubjectValues(csr.der),
        )
        val public = KEY.public as RSAPublicKey
        assertEquals(1024, public.modulus.bitLength())
        val requestInfo = derChildren(csr.der, readTlv(csr.der, 0)).first()
        val spki = derChildren(csr.der, requestInfo)[2]
        val spkiChildren = derChildren(csr.der, spki)
        assertEquals(0x03, spkiChildren[1].tag, "SPKI must carry the key as a BIT STRING")
        // Version INTEGER 0 and empty [0] attributes open/close the request info.
        val infoChildren = derChildren(csr.der, requestInfo)
        assertEquals(0x02, infoChildren[0].tag)
        assertEquals(BigInteger.ZERO, BigInteger(csr.der, infoChildren[0].bodyStart, infoChildren[0].bodyEnd - infoChildren[0].bodyStart))
        assertEquals(0xa0, infoChildren[3].tag)
        assertEquals(0, infoChildren[3].bodyEnd - infoChildren[3].bodyStart, "attributes must be empty")
    }

    @Test
    fun pemEncodesAndDecodesSixtyFourColumnBase64() {
        val der = ByteArray(200) { it.toByte() }
        val pem = Pem.encode(Pem.CSR_TYPE, der)
        assertTrue(pem.startsWith("-----BEGIN CERTIFICATE REQUEST-----\n"))
        assertTrue(pem.trimEnd().endsWith("-----END CERTIFICATE REQUEST-----"))
        assertContentEquals(der, Pem.decode(pem, Pem.CSR_TYPE))
    }

    @Test
    fun pemDecodeRejectsMissingOrUnterminatedBlocks() {
        assertFailsWith<IllegalArgumentException> { Pem.decode("nothing here", Pem.CSR_TYPE) }
        assertFailsWith<IllegalArgumentException> {
            Pem.decode("-----BEGIN CERTIFICATE REQUEST-----\nAAAA", Pem.CSR_TYPE)
        }
    }

    @Test
    fun csrRefusesNonRsaKeys() {
        val ec = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        assertFailsWith<IllegalArgumentException> { IdsCsrBuilder.create(ec, "cn") }
    }

    private companion object {
        val KEY: KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair()
    }
}
