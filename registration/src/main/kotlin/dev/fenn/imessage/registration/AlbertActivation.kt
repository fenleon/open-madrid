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
import java.net.URLEncoder
import java.security.KeyPair
import java.security.SecureRandom

/**
 * The FairPlay (certificate chain, signature) pair of spec §1.2. The signature is SHA-1 RSA
 * PKCS1v15 over the serialized ActivationInfo plist; both inputs come from the caller. The
 * default caller supply is the bundled community identity ([BundledFairPlaySigner], §7 item
 * 21 user decision); tests inject a scripted signer — the injection point stays overridable.
 */
class FairPlayMaterial(val certChain: ByteArray, val signature: ByteArray)

/**
 * Supplies the §1.2 FairPlay pair for one activation. [sign] receives the exact serialized
 * ActivationInfo plist bytes (§1.2: "FairPlay signing covers the serialized ActivationInfo
 * plist") and returns the chain and signature placed into the activation body.
 */
fun interface FairPlaySigner {
    fun sign(activationInfoPlist: ByteArray): FairPlayMaterial
}

/**
 * The nested ActivationInfoXML plist of spec §1.2 — keys `ActivationRandomness` (uppercase
 * UUIDv4), `ActivationState` ("Unactivated"), `BuildVersion`, `DeviceCertRequest` (the PEM
 * CSR as plist `<data>`), `DeviceClass`, `ProductType`, `ProductVersion`, `SerialNumber`,
 * `UniqueDeviceID`.
 */
data class AlbertActivationInfo(
    val activationRandomness: String,
    val buildVersion: String,
    /** `DeviceCertRequest` — the PEM CSR of §1.2 ([AlbertCsr.create]), sent as `<data>`(PEM). */
    val deviceCertRequestPem: String,
    val deviceClass: String = DEVICE_CLASS_MACOS,
    val productType: String,
    val productVersion: String,
    val serialNumber: String,
    val uniqueDeviceId: String,
) {
    fun toDict(): Map<String, Any?> = linkedMapOf(
        "ActivationRandomness" to activationRandomness,
        "ActivationState" to ACTIVATION_STATE,
        "BuildVersion" to buildVersion,
        // rev 26 (live 2026-10-03): the accepted request carries base64(PEM) — the PEM CSR TEXT
        // bytes in the `<data>`; a DER-encoded CSR is rejected server-side (the
        // SIGNATURE_VERIFICATION_FAILED page).
        "DeviceCertRequest" to deviceCertRequestPem.toByteArray(),
        "DeviceClass" to deviceClass,
        "ProductType" to productType,
        "ProductVersion" to productVersion,
        "SerialNumber" to serialNumber,
        "UniqueDeviceID" to uniqueDeviceId,
    )

    companion object {
        /** §1.2 records device class "MacOS" — matching the activation URL's `?device=MacOS`. */
        const val DEVICE_CLASS_MACOS = "MacOS"

        const val ACTIVATION_STATE = "Unactivated"

        /** An uppercase UUIDv4 (§1.2). */
        fun newActivationRandomness(random: SecureRandom = SecureRandom()): String {
            val bytes = ByteArray(16)
            random.nextBytes(bytes)
            bytes[6] = ((bytes[6].toInt() and 0x0f) or 0x40).toByte()
            bytes[8] = ((bytes[8].toInt() and 0x3f) or 0x80).toByte()
            val hex = bytes.joinToString("") { "%02x".format(it) }
            return buildString {
                append(hex, 0, 8); append('-')
                append(hex, 8, 12); append('-')
                append(hex, 12, 16); append('-')
                append(hex, 16, 20); append('-')
                append(hex, 20, 32)
            }.uppercase()
        }
    }
}

/**
 * The `DeviceCertRequest` CSR of spec §1.2 — recorded outright, not disagreed: a fresh
 * 1024-bit RSA key, CN "Client Push Certificate", OU "iPhone", O "Apple Inc.", signed
 * SHA-1WithRSA. The private key is client-generated and never sent; it later pairs with the
 * returned DeviceCertificate (courier connect field 12, §3.3).
 */
object AlbertCsr {
    const val COMMON_NAME = "Client Push Certificate"
    const val ORGANIZATIONAL_UNIT = "iPhone"
    const val ORGANIZATION = "Apple Inc."
    const val RSA_BITS = 1024

    /** The recorded self-signature hash (§1.2 "SHA-1WithRSA"). */
    val SELF_SIGNATURE_HASH = CsrSignatureHash.SHA1

    fun create(keyPair: KeyPair): IdsCsr =
        IdsCsrBuilder.create(
            keyPair,
            COMMON_NAME,
            ORGANIZATIONAL_UNIT,
            ORGANIZATION,
            SELF_SIGNATURE_HASH,
        )
}

/** The parsed Albert activation response (§1.2: `device-activation` → `activation-record`). */
data class AlbertActivationResponse(
    /** The device certificate (PEM) — client key never sent, so this is the only returned material. */
    val deviceCertificatePem: String?,
    /** `ack-received` / `show-settings` — value types not recorded (§1.2), carried verbatim. */
    val ackReceived: Any?,
    val showSettings: Any?,
    val raw: Map<String, Any?>,
    /**
     * Redacted body excerpt carried when Apple refused (no DeviceCertificate) — the wrapped-UI
     * refusal states its reason in page text (rev 26, live 2026-10-02). Diagnostic only.
     */
    val refusalBody: String? = null,
)

/**
 * The Albert activation of spec §1.2 (C8's wire half): POST form-urlencoded with the single
 * form key `activation-info`, whose value is an XML plist carrying `ActivationInfoComplete`
 * (true), `ActivationInfoXML` (the nested XML plist), `FairPlayCertChain` and
 * `FairPlaySignature`. No timestamp is sent; no Apple-Account login is needed (§1.1).
 *
 * The response's outer `<Protocol>` block is plist-parsed ([XmlPlist.decodeProtocol]):
 * `device-activation` → `activation-record` → `DeviceCertificate` (PEM), plus
 * `ack-received`/`show-settings`. No device token appears in the response (§1.2).
 */
class AlbertActivator(
    private val http: IdsHttp,
    private val url: String = DEFAULT_URL,
    private val fairPlay: FairPlaySigner = BundledFairPlaySigner(),
) {

    suspend fun activate(
        info: AlbertActivationInfo,
        fairPlay: FairPlaySigner = this.fairPlay,
    ): AlbertActivationResponse {
        val activationInfoXml = XmlPlist.encode(info.toDict())
        val material = fairPlay.sign(activationInfoXml)
        val body = linkedMapOf<String, Any?>(
            "ActivationInfoComplete" to true,
            "ActivationInfoXML" to activationInfoXml.toString(Charsets.UTF_8),
            "FairPlayCertChain" to material.certChain,
            "FairPlaySignature" to material.signature,
        )
        val form = FORM_KEY + "=" + URLEncoder.encode(
            XmlPlist.encode(body).toString(Charsets.UTF_8),
            Charsets.UTF_8,
        )
        val response = http.post(url, emptyMap(), form.toByteArray(Charsets.UTF_8), CONTENT_TYPE)
        if (response.status != 200) throw IdsActivationException("POST $url → HTTP ${response.status}")
        return parseResponse(response.body)
    }

    private fun parseResponse(bytes: ByteArray): AlbertActivationResponse {
        val dict = try {
            XmlPlist.decodeProtocol(bytes)
        } catch (e: PlistFormatException) {
            throw IdsActivationException("activation response is not a plist: ${e.message}", e)
        }
        val root = stringKeyedDictOrNull(dict)
            ?: throw IdsActivationException("activation response is ${typeName(dict)}, expected a dict")
        val activationRecord = when (val deviceActivation = root["device-activation"]) {
            null -> null
            is Map<*, *> -> deviceActivation["activation-record"] as? Map<*, *>
                ?: throw IdsActivationException(
                    "activation response has 'device-activation' but no 'activation-record' dict",
                )
            else -> throw IdsActivationException(
                "activation 'device-activation' is ${typeName(deviceActivation)}, expected a dict",
            )
        }
        // Apple wraps the PEM text in plist `<data>` (rev 26, live 2026-10-03: base64(PEM)
        // inside the activation record) — the XML decode yields bytes; the plain-string form
        // (§1.2's original recording) is accepted too.
        val certificate = when (val v = activationRecord?.get("DeviceCertificate")) {
            is String -> v
            is ByteArray -> String(v, Charsets.UTF_8)
            else -> null
        }
        val refusalBody = if (certificate == null) {
            // Apple's refusal answers carry no certificate; a wrapped-UI one (rev 26, live
            // 2026-10-02: empty record + a `<Document>` page) states the reason in its text.
            // Carry a redacted excerpt — data blobs stripped, whitespace collapsed.
            String(bytes, Charsets.UTF_8)
                .replace(Regex("<[a-zA-Z0-9]*Data>[^<]*</[a-zA-Z0-9]*Data>"), "<data>")
                .replace(Regex("\\s+"), " ")
                .take(4000)
        } else null
        return AlbertActivationResponse(
            deviceCertificatePem = certificate,
            ackReceived = root["ack-received"],
            showSettings = root["show-settings"],
            raw = root,
            refusalBody = refusalBody,
        )
    }

    companion object {
        /** The recorded activation endpoint (§1.2). */
        const val DEFAULT_URL = "https://albert.apple.com/deviceservices/deviceActivation?device=MacOS"

        /** The single form key (§1.2). */
        const val FORM_KEY = "activation-info"

        const val CONTENT_TYPE = "application/x-www-form-urlencoded"
    }
}
