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
/** GSA login-chain HTTP or wire failure (spec §1.5). */
class GsaLoginException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** The `Status` dict of a §1.5 GSA response: integer `ec` (0 = ok) and string `em`. */
data class GsaStatus(
    val ec: Int,
    val em: String?,
    /** Apple returns `au` INSIDE the Status dict (reference: apple-private-apis reads
     *  `status.get("au")` — the top-level Response dict has no `au`). */
    val au: String? = null,
) {
    companion object {
        const val EC_OK = 0

        /** §1.5: the complete response's `au` selects the secondary-auth variant. */
        const val AU_SECONDARY_AUTH = "secondaryAuth"
        const val AU_TRUSTED_DEVICE = "trustedDeviceSecondaryAuth"
    }
}

/** The init request of §1.5: `A2k`, `cpd`, `o` = `init`, `ps`, `u` under the `Header`/`Request` wrapper. */
data class GsaInitRequest(
    val username: String,
    /** The client SRP public value A (§1.5) — plist data. */
    val a2k: ByteArray,
    /** The §1.5 cpd dictionary (built through [GsaCpd]). */
    val cpd: Map<String, Any?>,
    /** The offered password protocols; the recorded `ps` array (§1.5). */
    val protocols: List<String> = GsaSrpPasswordKey.OFFERED_PROTOCOLS,
    /** §1.5: the anisette base headers (filtered set) ride the POSTs. */
    val headers: Map<String, String> = emptyMap(),
)

/** The init response under `Response` (§1.5). */
data class GsaInitResponse(
    /** `s` — the server salt (plist data). */
    val salt: ByteArray,
    /** `B` — the server public value (plist data, used verbatim in the hashes). */
    val serverPublic: ByteArray,
    /** `i` — the PBKDF2 iteration count. */
    val iterations: Int,
    /** `c` — the challenge string echoed in the complete request. */
    val challenge: String,
    /** `sp` — the selected password protocol; default `s2k` when absent (§1.5). */
    val protocol: String,
    val status: GsaStatus,
    val raw: Map<String, Any?>,
)

/** The complete request of §1.5: `M1`, `c`, `cpd`, `o` = `complete`, `u`. */
data class GsaCompleteRequest(
    val username: String,
    val m1: ByteArray,
    val challenge: String,
    val cpd: Map<String, Any?>,
    /** §1.5: the anisette base headers (filtered set) ride the POSTs. */
    val headers: Map<String, String> = emptyMap(),
)

/**
 * The complete response under `Response` (§1.5): `M2` (server proof), `spd` (encrypted plist
 * data), `Status` whose `au` string selects secondary auth when present. [pet] carries the
 * `X-Apple-PE-Token` of the response headers when one was sent (§1.5 PET).
 */
data class GsaCompleteResponse(
    /** `M2` — verified against the computed proof by [GsaLoginClient.complete]. */
    val m2: ByteArray?,
    /** `spd` — encrypted; decrypt with [GsaSpdDecryptor] and the session key K. */
    val spd: ByteArray?,
    /** `au` — secondary-auth selector; absent (null) means the login completed as logged-in. */
    val secondaryAuth: String?,
    val status: GsaStatus,
    val pet: GsaPet?,
    val raw: Map<String, Any?>,
)

/**
 * The two GSA SRP POSTs of spec §1.5, both to `https://gsa.apple.com/grandslam/GsService2`
 * with `Content-Type: text/x-xml-plist` and the `Header`/`Request` XML-plist wrapper
 * (`Header` carries only `Version` = `1.0.1`).
 *
 * The transport is injected ([IdsHttp]); the Apple root CA pin applies to GSA traffic too
 * (§1.1/§1.5) — production passes the pinned [AppleTrust] pool. No credential material (SRP
 * values, proofs, keys, tokens) is ever passed to [logEvent].
 */
class GsaLoginClient(
    private val http: IdsHttp,
    private val endpoint: String = GSA_ENDPOINT,
    private val logEvent: (String) -> Unit = {},
) {

    suspend fun init(request: GsaInitRequest): GsaInitResponse {
        logEvent("gsa: init")
        val response = post(XmlPlist.encode(request.toBody()), request.headers)
        val dict = responseDict(response, "init")
        val status = statusOf(dict, "init")
        if (status.ec != GsaStatus.EC_OK) throw GsaLoginException("GSA init failed: ec=${status.ec} em=${status.em ?: "-"}")
        return GsaInitResponse(
            salt = dataField(dict, "s", "init response"),
            serverPublic = dataField(dict, "B", "init response"),
            iterations = (integerOrNull(dict["i"])
                ?: throw GsaLoginException("GSA init response has no integer 'i' iteration count (§1.5)"))
                .also { if (it <= 0) throw GsaLoginException("GSA init response 'i' iteration count is $it") },
            challenge = dict["c"] as? String
                ?: throw GsaLoginException("GSA init response has no 'c' challenge string (§1.5)"),
            protocol = dict["sp"] as? String ?: GsaSrpPasswordKey.PROTOCOL_S2K,
            status = status,
            raw = dict,
        )
    }

    suspend fun complete(request: GsaCompleteRequest, nowEpochMs: Long): GsaCompleteResponse {
        logEvent("gsa: complete")
        val response = post(XmlPlist.encode(request.toBody()), request.headers)
        val dict = responseDict(response, "complete")
        val status = statusOf(dict, "complete")
        val secondaryAuth = status.au
        if (secondaryAuth == null && status.ec != GsaStatus.EC_OK) {
            throw GsaLoginException("GSA complete failed: ec=${status.ec} em=${status.em ?: "-"}")
        }
        return GsaCompleteResponse(
            m2 = dict["M2"] as? ByteArray,
            spd = dict["spd"] as? ByteArray,
            secondaryAuth = secondaryAuth,
            status = status,
            pet = GsaTokenHeaders.pet(response.headers.header(HEADER_PE_LOWER), nowEpochMs),
            raw = dict,
        )
    }

    private fun Map<String, String>.header(lowercasedName: String): String? =
        entries.firstOrNull { it.key.equals(lowercasedName, ignoreCase = true) }?.value

    private suspend fun post(encoded: ByteArray, headers: Map<String, String>): IdsHttpResponse {
        val response = http.post(endpoint, headers, encoded, CONTENT_TYPE)
        if (response.status != 200) {
            throw GsaLoginException("GSA POST $endpoint → HTTP ${response.status}")
        }
        return response
    }

    private fun responseDict(response: IdsHttpResponse, step: String): Map<String, Any?> {
        val parsed = try {
            Plist.parse(response.body)
        } catch (e: PlistFormatException) {
            throw GsaLoginException("GSA $step response is not a plist: ${e.message}", e)
        }
        val top = stringKeyedDictOrNull(parsed)
            ?: throw GsaLoginException("GSA $step response is ${typeName(parsed)}, expected a dict")
        val inner = stringKeyedDictOrNull(top["Response"])
            ?: throw GsaLoginException(
                "GSA $step response has no 'Response' dict (${typeName(top["Response"])}) — spec §1.5",
            )
        return inner
    }

    private fun statusOf(dict: Map<String, Any?>, step: String): GsaStatus {
        val status = stringKeyedDictOrNull(dict["Status"])
            ?: throw GsaLoginException("GSA $step response has no 'Status' dict (§1.5)")
        return GsaStatus(
            ec = integerOrNull(status["ec"])
                ?: throw GsaLoginException("GSA $step 'Status' has no integer 'ec' (§1.5)"),
            em = status["em"] as? String,
            au = status["au"] as? String,
        )
    }

    private fun dataField(dict: Map<String, Any?>, key: String, where: String): ByteArray =
        dict[key] as? ByteArray
            ?: throw GsaLoginException("GSA $where has no '$key' data field (§1.5, got ${typeName(dict[key])})")

    private fun GsaInitRequest.toBody(): Map<String, Any?> = linkedMapOf(
        "Header" to linkedMapOf("Version" to HEADER_VERSION),
        "Request" to linkedMapOf<String, Any?>(
            "A2k" to a2k,
            "cpd" to cpd,
            "o" to OPERATION_INIT,
            "ps" to protocols,
            "u" to username,
        ),
    )

    private fun GsaCompleteRequest.toBody(): Map<String, Any?> = linkedMapOf(
        "Header" to linkedMapOf("Version" to HEADER_VERSION),
        "Request" to linkedMapOf<String, Any?>(
            "M1" to m1,
            "c" to challenge,
            "cpd" to cpd,
            "o" to OPERATION_COMPLETE,
            "u" to username,
        ),
    )

    companion object {
        const val GSA_ENDPOINT = "https://gsa.apple.com/grandslam/GsService2"
        const val CONTENT_TYPE = "text/x-xml-plist"
        const val HEADER_VERSION = "1.0.1"
        const val OPERATION_INIT = "init"
        const val OPERATION_COMPLETE = "complete"

        /** Response headers are lower-cased by the seam (§1.5 token headers). */
        const val HEADER_PE_LOWER = "x-apple-pe-token"
    }
}
