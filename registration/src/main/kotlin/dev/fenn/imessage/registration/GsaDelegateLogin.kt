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
import java.util.Base64

/**
 * One iCloud sign-in request of spec §1.5: the XML-plist body (`delegates`, `protocolVersion`,
 * `userInfo`) and the recorded header set. `X-Mme-Nas-Qualify` (the validation blob) is minted
 * by the chunk-C device verification (§1.1) — caller-supplied here.
 *
 * Recorded values (C59) as defaults: `userInfo.timezone` = the hardcoded IANA name
 * (`America/New_York` in the reference config), and the `X-Mme-Client-Info` recorded bracketed
 * AOSKit form `<HardwareModel> <OSname;OSversion;OSbuild> <AOSKit form>` (§1.5 rev-15 closure) —
 * the device slots are device-dependent, so the bare recorded AOSKit inner component
 * ([GsaDelegateLoginClient.AOSKIT_CLIENT_INFO]) is the struct's fallback default;
 * [GsaHeaderConfig.signInClientInfo] builds the exact bracketed form, and
 * [GsaLoginChain.idsDelegateCredentials] defaults to it when the device config is wired.
 */
data class IcloudSignInRequest(
    /** The Apple-ID username — the Basic auth username with the PET as password (§1.5). */
    val username: String,
    /** The PET (§1.5) — never logged. */
    val pet: String,
    /** `X-Apple-ADSID` (§1.5, from the decrypted spd). */
    val adsid: String,
    /** The §1.1 validation blob, base64'd into `X-Mme-Nas-Qualify`. */
    val validationData: ByteArray,
    /** `userInfo`'s client id — sent as the kebab-case wire key `client-id`, uppercase UUIDv4 (§1.5, rev 26). */
    val clientId: String,
    /** `userInfo.timezone` — the recorded hardcoded-IANA-name default (§1.5 C59). */
    val timezone: String = GsaDelegateLoginClient.SIGNIN_TIMEZONE,
    /** `X-Mme-Client-Info` — the recorded AOSKit form as default (§1.5 C59). */
    val clientInfo: String = GsaDelegateLoginClient.AOSKIT_CLIENT_INFO,
    /** The full §1.1 anisette header set. */
    val anisette: Map<String, String>,
)

/** One `delegates` entry of the sign-in response (§1.5: `status`, `statusMessage`, `serviceData`). */
data class IcloudDelegateResult(
    val status: Int?,
    val statusMessage: String?,
    val serviceData: Map<String, Any?>?,
    val raw: Map<String, Any?>,
)

/** The iCloud sign-in response of spec §1.5. */
data class IcloudSignInResponse(
    /** 0 = ok (§1.5). */
    val status: Int,
    val localizedError: String?,
    val delegates: Map<String, IcloudDelegateResult>,
    val raw: Map<String, Any?>,
) {
    /**
     * The IDS delegate's kebab-case serviceData → the §1.2 authenticate inputs: the `auth-token`
     * (sent as `authentication-data` = {`auth-token`: token}) and the `profile-id` (realm user
     * id). Loud on a missing or non-ok delegate — spec §1.5.
     */
    fun idsDelegateCredentials(): IdsDelegateCredentials {
        if (status != GsaDelegateLoginClient.STATUS_OK) {
            throw GsaLoginException(
                "iCloud sign-in status $status (${localizedError ?: "no localizedError"}) — spec §1.5",
            )
        }
        val delegate = delegates[GsaDelegateLoginClient.IDS_DELEGATE_BUNDLE_ID]
            ?: throw GsaLoginException(
                "iCloud sign-in response has no ${GsaDelegateLoginClient.IDS_DELEGATE_BUNDLE_ID} delegate " +
                    "(§1.5; has ${delegates.keys})",
            )
        if (delegate.status != GsaDelegateLoginClient.STATUS_OK) {
            throw GsaLoginException(
                "${GsaDelegateLoginClient.IDS_DELEGATE_BUNDLE_ID} delegate status ${delegate.status} " +
                    "(${delegate.statusMessage ?: "no statusMessage"}) — spec §1.5",
            )
        }
        val serviceData = delegate.serviceData
            ?: throw GsaLoginException(
                "${GsaDelegateLoginClient.IDS_DELEGATE_BUNDLE_ID} delegate carries no serviceData (§1.5) — " +
                    "delegate keys=${delegate.raw.keys}, top-level keys=${raw.keys}, delegate scalars=" +
                    delegate.raw.entries.filter { it.value !is Map<*, *> }
                        .joinToString { "${it.key}=${it.value}" },
            )
        val authToken = serviceData["auth-token"] as? String
            ?: throw GsaLoginException(
                "IDS delegate serviceData has no 'auth-token' string (§1.5, got ${typeName(serviceData["auth-token"])})",
            )
        val profileId = serviceData["profile-id"] as? String
            ?: throw GsaLoginException(
                "IDS delegate serviceData has no 'profile-id' string (§1.5, got ${typeName(serviceData["profile-id"])})",
            )
        return IdsDelegateCredentials(authToken, profileId)
    }
}

/** The IDS delegate credentials the §1.2 authenticate exchange consumes (spec §1.5). */
data class IdsDelegateCredentials(
    /** Sent as `authentication-data` = {`auth-token`: token} (§1.2). */
    val authToken: String,
    /** The realm user id (§1.2). */
    val profileId: String,
)

/**
 * The delegate login of spec §1.5: POST `https://setup.icloud.com/setup/signin/v2/login` with
 * Basic `username:PET` auth and the recorded header set; the response's `com.apple.private.ids`
 * delegate serviceData yields the IDS `authToken`/`profileId`.
 */
class GsaDelegateLoginClient(
    private val http: IdsHttp,
    private val endpoint: String = SIGNIN_ENDPOINT,
    private val logEvent: (String) -> Unit = {},
) {

    suspend fun signIn(request: IcloudSignInRequest): IcloudSignInResponse {
        logEvent("gsa: iCloud sign-in")
        val basic = Base64.getEncoder()
            .encodeToString("${request.username}:${request.pet}".toByteArray(Charsets.UTF_8))
        val headers = buildMap {
            putAll(request.anisette)
            put("Authorization", "Basic $basic")
            put(HEADER_NAS_QUALIFY, Base64.getEncoder().encodeToString(request.validationData))
            put(HEADER_ADSID, request.adsid)
            put(HEADER_CLIENT_INFO, request.clientInfo)
            put("User-Agent", SIGNIN_USER_AGENT)
        }
        val body = linkedMapOf<String, Any?>(
            "delegates" to linkedMapOf<String, Any?>(
                IDS_DELEGATE_BUNDLE_ID to linkedMapOf("protocol-version" to "4"),
                MOBILEME_DELEGATE_BUNDLE_ID to linkedMapOf<String, Any?>(),
            ),
            "protocolVersion" to PROTOCOL_VERSION,
            "userInfo" to linkedMapOf<String, Any?>(
                // rev 26 (live 2026-10-04): the sign-in body's client id rides kebab-case
                // (`client-id` — the recorded upstream identity struct is kebab-case on the
                // wire); "clientId" was the one body delta vs the live request capture.
                "client-id" to request.clientId,
                "language" to "en-US",
                "timezone" to request.timezone,
            ),
        )
        val encoded = XmlPlist.encode(body)
        val response = http.post(endpoint, headers, encoded, CONTENT_TYPE)
        if (response.status != 200) {
            throw GsaLoginException(
                "iCloud sign-in POST $endpoint → HTTP ${response.status}${errorDetail(response.body)}",
            )
        }
        return parseResponse(response.body)
    }

    /** Top-level error-shape facts only (keys, integer codes, error strings) — never token values. */
    private fun errorDetail(bytes: ByteArray): String {
        val parsed = try {
            Plist.parse(bytes)
        } catch (_: Exception) {
            return ""
        }
        val dict = stringKeyedDictOrNull(parsed) ?: return " (${typeName(parsed)})"
        val scalars = dict.entries
            .mapNotNull { (k, v) ->
                when {
                    v is Int || v is Long -> "$k=$v"
                    v is String && k !in setOf("dsid", "auth-token", "adsid") -> "$k=$v"
                    v is Map<*, *> -> "$k keys=${stringKeyedDictOrNull(v)?.keys ?: v.keys}"
                    else -> null
                }
            }
            .joinToString(", ")
        return " — body: $scalars"
    }

    private fun parseResponse(bytes: ByteArray): IcloudSignInResponse {
        val parsed = try {
            Plist.parse(bytes)
        } catch (e: PlistFormatException) {
            throw GsaLoginException("iCloud sign-in response is not a plist: ${e.message}", e)
        }
        val dict = stringKeyedDictOrNull(parsed)
            ?: throw GsaLoginException("iCloud sign-in response is ${typeName(parsed)}, expected a dict")
        val delegates = when (val value = dict["delegates"]) {
            null -> emptyMap()
            is Map<*, *> -> stringKeyedDictOrNull(value)?.mapValues { (_, entry) ->
                parseDelegate(stringKeyedDictOrNull(entry)
                    ?: throw GsaLoginException(
                        "iCloud sign-in delegates entry is ${typeName(entry)}, expected a dict",
                    ))
            } ?: throw GsaLoginException("iCloud sign-in 'delegates' has non-string keys (§1.5)")
            else -> throw GsaLoginException("iCloud sign-in 'delegates' is ${typeName(value)}, expected a dict")
        }
        return IcloudSignInResponse(
            status = integerOrNull(dict["status"])
                ?: throw GsaLoginException("iCloud sign-in response has no integer 'status' (§1.5)"),
            localizedError = dict["localizedError"] as? String,
            delegates = delegates,
            raw = dict,
        )
    }

    // Apple's live sign-in response is kebab-case (rev 26, live 2026-10-04: delegate keys =
    // [status, service-data, account-exists]); the camelCase fallback keeps the §1.5
    // extraction recording parseable.
    private fun parseDelegate(dict: Map<String, Any?>) = IcloudDelegateResult(
        status = integerOrNull(dict["status"]),
        statusMessage = (dict["status-message"] ?: dict["statusMessage"]) as? String,
        serviceData = (dict["service-data"] ?: dict["serviceData"])?.let {
            stringKeyedDictOrNull(it)
                ?: throw GsaLoginException("delegate service-data is ${typeName(it)}, expected a dict (§1.5)")
        },
        raw = dict,
    )

    companion object {
        const val SIGNIN_ENDPOINT = "https://setup.icloud.com/setup/signin/v2/login"
        const val CONTENT_TYPE = "application/x-apple-plist"
        const val PROTOCOL_VERSION = "1.0"
        const val IDS_DELEGATE_BUNDLE_ID = "com.apple.private.ids"
        const val MOBILEME_DELEGATE_BUNDLE_ID = "com.apple.mobileme"
        const val HEADER_NAS_QUALIFY = "X-Mme-Nas-Qualify"
        const val HEADER_ADSID = "X-Apple-ADSID"
        const val HEADER_CLIENT_INFO = "X-Mme-Client-Info"
        const val STATUS_OK = 0

        /**
         * The recorded sign-in `User-Agent` (§1.5 C59): a static config constant. The reference
         * composes it via a parser quirk into the duplicated-token string — the full static
         * string is the recorded form.
         */
        const val SIGNIN_USER_AGENT = "com.apple.iCloudHelper/282 com.apple.iCloudHelper/282"

        /** The recorded `userInfo.timezone` default — a hardcoded IANA name (§1.5 C59). */
        const val SIGNIN_TIMEZONE = "America/New_York"

        /**
         * The recorded AOSKit form the sign-in `X-Mme-Client-Info` wraps (§1.5 C59). The recorded
         * full header is the bracketed form `<HardwareModel> <OSname;OSversion;OSbuild> <this>`
         * (§1.5 rev-15 closure) — device-dependent, built by [GsaHeaderConfig.signInClientInfo];
         * this bare inner form is the fallback default without device slots.
         */
        const val AOSKIT_CLIENT_INFO = "com.apple.AOSKit/282 (com.apple.accountsd/113)"
    }
}
