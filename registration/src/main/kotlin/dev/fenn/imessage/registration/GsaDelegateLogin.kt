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
 * The delegate login of spec §1.5: POST the configured endpoint (the recorded
 * `/setup/signin/v2/login` with the V2 body + Basic auth; the vendored reference's
 * `/setup/prefpane/login` with the V1 `AuthRequest` body — credentials in the body,
 * RE 2026-10-13) with the recorded header set; the response's `com.apple.private.ids`
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
        val delegates = linkedMapOf<String, Any?>(
            IDS_DELEGATE_BUNDLE_ID to linkedMapOf("protocol-version" to "4"),
            MOBILEME_DELEGATE_BUNDLE_ID to linkedMapOf<String, Any?>(),
        ) // The vendored reference (open_absinthe, RE 2026-10-13) ships ONLY the V1 request
        // shape on this endpoint: kebab-case `AuthRequest {apple-id, client-id, delegates,
        // password}` with the PET in the body — the .so has no V2AuthRequest/protocolVersion/
        // userInfo strings at all. Basic `username:PET` still rides (the closure's
        // basic_auth needs no string constants; live 2026-10-13: V1 body WITHOUT Basic →
        // 401 UNAUTHORIZED, so the server reads Basic even on the V1 shape). The V2 wrapper
        // is kept for the recorded v2 endpoint (§1.5 C59).
        val prefpane = endpoint == PREFPANE_ENDPOINT
        // The captured prefpane request (vendored client, live 2026-10-14, /tmp/ob-req-002.bin)
        // carries NO X-Apple-I-MD-LU and DOES carry X-Apple-Locale/X-Apple-I-Timezone — the
        // inverse of the GSA cpd header set (headersFor() adds MD-LU, drops both). MD-LU here is
        // a machine-identity header (real macOS sends its AuthKit local-user UUID) and the
        // endpoint's verdict is ICLOUD_INVALID_DEVICE_TOKEN — the fabricated sha256(keychain-id)
        // form is the prime suspect for the 400. GSA keeps its recorded set (rev 15).
        val anisette = if (prefpane) {
            request.anisette
                .filterKeys { !it.equals("X-Apple-I-MD-LU", true) }
                // The accepted prefpane request's exact wire casing (live capture 2026-10-14,
                // captures/c56k/mint-repro/ob-req-002.bin): real AuthKit sends mixed-case
                // Md/Adsid/Timezone, while the §1.1-recorded GSA names carry all-caps
                // MD/ADSID/TimeZone — and setup.icloud.com answers ICLOUD_INVALID_DEVICE_TOKEN
                // with the caps forms at full value parity (2026-10-14 byte diff), so the
                // endpoint is treated as case-sensitive. GSA keeps its recorded (working) set.
                .mapKeys { (k, _) -> PREFPANE_HEADER_CASE[k.lowercase()] ?: k } +
                mapOf(
                    "X-Apple-Locale" to "en_US",
                    "X-Apple-I-Timezone" to "UTC",
                    // fresh per request, the get_headers Z form (capture 2026-10-14)
                    "X-Apple-I-Client-Time" to iso8601Z(System.currentTimeMillis()),
                )
        } else {
            request.anisette
        }
        val body = if (prefpane) {
            linkedMapOf<String, Any?>(
                "apple-id" to request.username,
                "client-id" to request.clientId.lowercase(),
                "delegates" to delegates,
                "password" to request.pet,
            )
        } else {
            linkedMapOf<String, Any?>(
                "delegates" to delegates,
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
        }
        val headers = buildMap {
            putAll(anisette)
            put("Authorization", "Basic $basic")
            put(HEADER_NAS_QUALIFY, Base64.getEncoder().encodeToString(request.validationData))
            // Mixed case on the prefpane path (see PREFPANE_HEADER_CASE): the accepted
            // request carries X-Apple-Adsid, the recorded GSA name is all-caps ADSID.
            put(if (prefpane) "X-Apple-Adsid" else HEADER_ADSID, request.adsid)
            // The captured prefpane request (vendored client, live 2026-10-14, /tmp/ob-req-002.bin)
            // carries the AuthKit/MobileSMS inner component here, not the AOSKit form the v2
            // endpoint was recorded with.
            put(HEADER_CLIENT_INFO, if (prefpane) PREFPANE_CLIENT_INFO else request.clientInfo)
            put("User-Agent", SIGNIN_USER_AGENT)
        }
        val encoded = XmlPlist.encode(body)
        // A/B instrumentation: dump the exact outgoing request (headers + body) when the
        // marker exists, for a host-side rustls replay with byte-identical content. The
        // dump carries the Basic credential — /data/local/tmp only, never logged.
        if (java.io.File("/data/local/tmp/debug-capture-signin").isFile) {
            runCatching {
                java.io.File("/data/local/tmp/debug-last-signin.bin").writeBytes(
                    (listOf("POST $endpoint", "Content-Type: $CONTENT_TYPE") +
                        headers.entries.map { (k, v) -> "$k: $v" } + listOf("", "")).joinToString("\r\n")
                        .toByteArray(Charsets.UTF_8) + encoded,
                )
            }
        }
        // No Content-Type on the prefpane path: the captured accepted request sends the XML
        // body bare (reqwest default), BridgeHttp maps "" to no header. The recorded v2
        // endpoint keeps its content type.
        val response = http.post(endpoint, headers, encoded, if (prefpane) "" else CONTENT_TYPE)
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

        /**
         * The reference client's delegate sign-in endpoint — captured LIVE 2026-10-14 from the
         * vendored client under gdb (`/tmp/ob-req-002.bin`): the wire path is
         * `/setup/prefpane/loginDelegates`, NOT `/setup/prefpane/login` (the `.so`'s rodata
         * string table concatenation `…/login` ‖ `Delegates…` misread rev 45 — `login` is the
         * plain machine sign-in whose failure dialog is exactly the 400
         * `ICLOUD_INVALID_DEVICE_TOKEN` every on-device attempt answered). The successful
         * sign-in CREATES the account's device record (live 2026-10-14: after the user removed
         * the record, the reference's next sign-in re-added it — no 2FA needed, stored-hash
         * re-auth).
         */
        const val PREFPANE_ENDPOINT = "https://setup.icloud.com/setup/prefpane/loginDelegates"

        /** The accepted prefpane request's exact anisette wire casing (live 2026-10-14,
         * ob-req-002.bin) — see the mapKeys call in [signIn]. */
        private val PREFPANE_HEADER_CASE = mapOf(
            "x-apple-i-md" to "X-Apple-I-Md",
            "x-apple-i-md-m" to "X-Apple-I-Md-M",
            "x-apple-i-md-rinfo" to "X-Apple-I-Md-Rinfo",
            "x-apple-i-timezone" to "X-Apple-I-Timezone",
        )

        /** The captured prefpane `X-Mme-Client-Info` inner component (live 2026-10-14). */
        const val PREFPANE_CLIENT_INFO =
            "<MacBookPro18,3> <macOS;26.6.2;25G83> <com.apple.AuthKit/1 (com.apple.MobileSMS/1262.500.151.1.2)>"
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
