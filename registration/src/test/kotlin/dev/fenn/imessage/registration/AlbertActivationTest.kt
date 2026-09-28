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
import java.net.URLDecoder
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

class AlbertActivationTest {

    private val fairPlayChain = ByteArray(32) { (it + 1).toByte() }
    private val fairPlaySignature = ByteArray(64) { (it + 7).toByte() }
    private var signedPlist: ByteArray? = null

    private fun info() = AlbertActivationInfo(
        activationRandomness = "A1B2C3D4-E5F6-4A1B-8C2D-9E0F1A2B3C4D",
        buildVersion = "23B85",
        deviceCertRequestPem = PUSH_CSR.pem,
        productType = "Mac15,12",
        productVersion = "14.6.1",
        serialNumber = "C02TEST123",
        uniqueDeviceId = "0123456789abcdef0123456789abcdef01234567",
    )

    private fun signer() = FairPlaySigner { plist ->
        signedPlist = plist
        FairPlayMaterial(fairPlayChain, fairPlaySignature)
    }

    private fun activator(http: IdsHttp, url: String = AlbertActivator.DEFAULT_URL) =
        AlbertActivator(http, url)

    @Test
    fun requestCarriesTheRecordedFormAndPlistShape() = runBlocking {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), okResponse())))
        activator(http).activate(info(), signer())

        val call = http.calls.single()
        assertEquals(AlbertActivator.DEFAULT_URL, call.url)
        assertEquals(AlbertActivator.CONTENT_TYPE, call.contentType)
        assertTrue(call.body.decodeToString().startsWith(AlbertActivator.FORM_KEY + "="))

        // One form key (§1.2); its URL-decoded value is the activation-info XML plist.
        val formValue = URLDecoder.decode(call.body.decodeToString().substringAfter('='), Charsets.UTF_8)
        val outer = Plist.parse(formValue.toByteArray()) as Map<*, *>
        assertEquals(
            setOf("ActivationInfoComplete", "ActivationInfoXML", "FairPlayCertChain", "FairPlaySignature"),
            outer.keys,
        )
        assertEquals(true, outer["ActivationInfoComplete"])
        assertContentEquals(fairPlayChain, outer["FairPlayCertChain"] as ByteArray)
        assertContentEquals(fairPlaySignature, outer["FairPlaySignature"] as ByteArray)

        // The nested ActivationInfoXML plist carries exactly the nine recorded keys (§1.2).
        val nested = Plist.parse((outer["ActivationInfoXML"] as String).toByteArray()) as Map<*, *>
        assertEquals(
            setOf(
                "ActivationRandomness", "ActivationState", "BuildVersion", "DeviceCertRequest",
                "DeviceClass", "ProductType", "ProductVersion", "SerialNumber", "UniqueDeviceID",
            ),
            nested.keys,
        )
        assertEquals("Unactivated", nested["ActivationState"])
        assertEquals("MacOS", nested["DeviceClass"])
        assertEquals("A1B2C3D4-E5F6-4A1B-8C2D-9E0F1A2B3C4D", nested["ActivationRandomness"])
        assertEquals(PUSH_CSR.pem, nested["DeviceCertRequest"])
    }

    @Test
    fun fairPlaySignerReceivesTheSerializedActivationInfoPlist() = runBlocking {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), okResponse())))
        activator(http).activate(info(), signer())

        val signed = signedPlist!!
        val nestedBytes = XmlPlist.encode(info().toDict())
        assertContentEquals(nestedBytes, signed, "the FairPlay signature covers the serialized ActivationInfo plist")
    }

    @Test
    fun responseParsesDeviceCertificateFromTheProtocolBlock() = runBlocking {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), okResponse())))
        val response = activator(http).activate(info(), signer())

        assertEquals(DEVICE_CERT_PEM, response.deviceCertificatePem)
        assertEquals(true, response.ackReceived)
        assertEquals(false, response.showSettings)
    }

    @Test
    fun responseWithoutDeviceActivationParsesWithNullCertificate() = runBlocking {
        val response = XmlPlist.encode(mapOf("ack-received" to true)) // activation rejected — no record
        val http = ScriptedIdsHttp(
            listOf(IdsHttpResponse(200, emptyMap(), protocolWrap(response))),
        )
        val parsed = activator(http).activate(info(), signer())
        assertEquals(null, parsed.deviceCertificatePem)
        assertEquals(true, parsed.ackReceived)
    }

    @Test
    fun non200Throws() {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(403, emptyMap(), ByteArray(0))))
        assertFailsWith<IdsActivationException> {
            runBlocking { activator(http).activate(info(), signer()) }
        }
    }

    @Test
    fun responseOutsideAProtocolBlockThrows() {
        val http = ScriptedIdsHttp(
            listOf(IdsHttpResponse(200, emptyMap(), XmlPlist.encode(mapOf("device-activation" to 1L)))),
        )
        assertFailsWith<IdsActivationException> {
            runBlocking { activator(http).activate(info(), signer()) }
        }
    }

    @Test
    fun activationRandomnessIsAnUppercaseUuidV4() {
        val value = AlbertActivationInfo.newActivationRandomness(SecureRandom(byteArrayOf(1, 2, 3)))
        assertTrue(
            Regex("^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$")
                .matches(value),
            "not an uppercase UUIDv4: $value",
        )
    }

    @Test
    fun albertCsrMatchesTheRecordedConstants() {
        val csr = AlbertCsr.create(PUSH_KEY)
        assertEquals(
            listOf("Client Push Certificate", "iPhone", "Apple Inc."),
            csrSubjectValues(csr.der),
        )
        assertEquals(1024, (PUSH_KEY.public as java.security.interfaces.RSAPublicKey).modulus.bitLength())
        // §1.2: "SHA-1WithRSA" — recorded, not a C57 parameter here.
        val top = derChildren(csr.der, readTlv(csr.der, 0))
        val verifier = java.security.Signature.getInstance("SHA1withRSA")
        verifier.initVerify(PUSH_KEY.public)
        verifier.update(derFullBytes(csr.der, top[0]))
        assertTrue(verifier.verify(csr.der.copyOfRange(top[2].bodyStart + 1, top[2].bodyEnd)))
    }

    @Test
    fun thePrivateKeyIsNeverSent() = runBlocking {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), okResponse())))
        activator(http).activate(info(), signer())
        val wire = http.calls.single().body.decodeToString()
        assertFalse(wire.contains("PRIVATE KEY"), "private key material must never ride the wire")
        assertFalse(wire.contains("BEGIN RSA"), "no private-material armor on the wire")
    }

    private fun protocolWrap(plist: ByteArray): ByteArray {
        // The inner plist rides inside the Protocol element, so it carries no XML declaration of its own.
        val inner = plist.decodeToString().substring(plist.decodeToString().indexOf("<plist"))
        return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Protocol>
$inner</Protocol>""".toByteArray()
    }

    private fun okResponse(): ByteArray = protocolWrap(
        XmlPlist.encode(
            mapOf(
                "device-activation" to mapOf(
                    "activation-record" to mapOf("DeviceCertificate" to DEVICE_CERT_PEM),
                ),
                "ack-received" to true,
                "show-settings" to false,
            ),
        ),
    )

    private companion object {
        val DEVICE_CERT_PEM =
            "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n"

        val PUSH_KEY: KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair()
        val PUSH_CSR: IdsCsr = AlbertCsr.create(PUSH_KEY)
    }
}
