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
import java.security.SecureRandom
import java.util.Base64

/** The §1.1 validation-data exchange failure (steps 1–2 wire shapes, or the bag keys). */
class ValidationDataException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** The two validation bag keys (§1.1) — endpoint URLs come from the bag, never hardcoded. */
object ValidationBagKeys {
    const val CERT = "id-validation-cert"
    const val INITIALIZE = "id-initialize-validation"
}

/**
 * The recorded wire halves of the three-step exchange (spec §1.1 C56, steps 1–2 concrete):
 *
 * - Step 1 — GET the `id-validation-cert` bag URL; the response is a plist with a single
 *   `cert` data field.
 * - Step 2 — POST the `id-initialize-validation` bag URL, body = a single-key plist
 *   `session-info-request` (data), with NO anisette and NO authentication headers — body
 *   only — and the response carries `session-info` (data).
 *
 * The step-2 body is an XML plist (the extracted client serializes the request with the plist
 * XML writer) and is posted with no content-type (§1.1).
 */
class ValidationCertClient(
    private val http: IdsHttp,
    private val bags: IdsBagFetcher,
    private val logEvent: (String) -> Unit = {},
) {

    /** Step 1: the step-1 certificate (the chain the §1.1 context consumes, leaf first). */
    suspend fun fetchCertificate(): ByteArray {
        val url = bags.idsBag().url(ValidationBagKeys.CERT)
        logEvent("validation: fetching the id-validation-cert certificate")
        val response = http.get(url)
        if (response.status != 200) {
            throw ValidationDataException("GET $url → HTTP ${response.status} (§1.1 step 1)")
        }
        val dict = dictOf(response.body, "step-1 response")
        return dict["cert"] as? ByteArray
            ?: throw ValidationDataException(
                "step-1 response has no 'cert' data field (§1.1; got ${typeName(dict["cert"])})",
            )
    }

    /**
     * Step 2: POST the single-key `session-info-request` plist body — no anisette, no auth
     * headers (§1.1: body only) — and return the response's `session-info` data.
     */
    suspend fun initializeValidation(sessionInfoRequest: ByteArray): ByteArray {
        val url = bags.idsBag().url(ValidationBagKeys.INITIALIZE)
        logEvent("validation: initializing the validation session")
        val body = XmlPlist.encode(linkedMapOf("session-info-request" to sessionInfoRequest))
        val response = http.post(url, emptyMap(), body, CONTENT_TYPE)
        if (response.status != 200) {
            throw ValidationDataException("POST $url → HTTP ${response.status} (§1.1 step 2)")
        }
        val dict = dictOf(response.body, "step-2 response")
        return dict["session-info"] as? ByteArray
            ?: throw ValidationDataException(
                "step-2 response has no 'session-info' data field (§1.1; got ${typeName(dict["session-info"])})",
            )
    }

    private fun dictOf(body: ByteArray, what: String): Map<String, Any?> {
        val parsed = try {
            Plist.parse(body)
        } catch (e: PlistFormatException) {
            throw ValidationDataException("$what is not a plist (§1.1): ${e.message}", e)
        }
        return stringKeyedDictOrNull(parsed)
            ?: throw ValidationDataException("$what is ${typeName(parsed)}, expected a dict (§1.1)")
    }

    companion object {
        /**
         * The step-2 POST carries NO content-type: the extracted client posts the XML-plist body
         * through a client whose only default request header is `Accept-Language`, with no
         * content-type set on the request (§1.1 — our earlier `text/x-xml-plist` was an
         * unsupported inference from the §1.5 GSA posts, and is one of the pinned constants).
         */
        const val CONTENT_TYPE = ""
    }
}

/** One completed generation: the §1.1 validation blob and when it was minted. */
class ValidationData(
    /** The final blob — verbatim into the register body's `validation-data` field (§1.4). */
    val blob: ByteArray,
    /** Generation time; the 15-minute validity bound (§1.1) is server-side — callers decide freshness. */
    val generatedAtEpochMs: Long,
) {
    /** The blob base64 — the `X-Mme-Nas-Qualify` header value of the §1.5 sign-in POST. */
    fun nasQualify(): String = Base64.getEncoder().encodeToString(blob)
}

/**
 * The §1.1 three-step exchange orchestrator: Mac identifiers (the helper-parser output or
 * caller-built) → step 1 + step 2 ([ValidationCertClient]) → the step-3 contract context
 * ([ValidationDataGenerator]) → the final blob ([ValidationData]).
 *
 * The blob is the hand-off point to the two recorded sinks, both of which take these bytes
 * verbatim and need no adapter: the IDS register body's `validation-data` field
 * ([IdsActivationRequest.validationData], §1.4) and, via [ValidationData.nasQualify], the
 * `X-Mme-Nas-Qualify` header of the §1.5 GSA delegate login
 * ([GsaLoginChain.idsDelegateCredentials]). Units stay separable — every stage is its own
 * class with injected transports.
 */
class ValidationDataExchange(
    private val http: IdsHttp,
    private val bags: IdsBagFetcher,
    private val strategies: ValidationDataStrategies = ValidationDataStrategies(),
    private val random: SecureRandom = SecureRandom(),
    private val logEvent: (String) -> Unit = {},
) {

    /**
     * Runs the recorded steps 1–2 against the bag URLs and the reconstruction step 3 in
     * [ValidationDataGenerator]; returns the final blob. [nowEpochMs] stamps the result.
     */
    suspend fun generate(identifiers: MacHardwareIdentifiers, nowEpochMs: Long): ValidationData {
        val hardware = HardwareConfiguration.from(identifiers)
        val client = ValidationCertClient(http, bags, logEvent)
        val certificate = client.fetchCertificate()
        val context = ValidationDataGenerator(
            certificateChain = listOf(certificate),
            hardware = hardware,
            strategies = strategies,
            random = random,
        )
        val sessionInfoRequest = context.createSessionInfoRequest()
        val sessionInfo = client.initializeValidation(sessionInfoRequest)
        context.establishKeys(sessionInfo)
        val blob = context.sign()
        logEvent("validation: blob generated")
        return ValidationData(blob, nowEpochMs)
    }
}
