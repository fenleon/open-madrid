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
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject

/**
 * One trusted-phone-number entry of the §1.5 `AuthenticationExtras` JSON (recorded fields:
 * `numberWithDialCode`, `lastTwoDigits`, `pushMode`, `id`).
 */
data class GsaTrustedPhoneNumber(
    val numberWithDialCode: String?,
    val lastTwoDigits: String?,
    val pushMode: Boolean?,
    val id: Long?,
    val raw: Map<String, String?>,
)

/** The parsed `AuthenticationExtras` of `GET https://gsa.apple.com/auth` (§1.5). */
data class GsaAuthExtras(
    val trustedPhoneNumbers: List<GsaTrustedPhoneNumber>,
)

/** The token headers a successful 2FA exchange returns (§1.5: tokens in response headers). */
data class GsaSecondaryAuthTokens(
    /** `X-Apple-GS-Token` — one per GSA service, keyed by service id. */
    val gsTokens: Map<String, GsaTokenHeader>,
    /** `X-Apple-HB-Token` occurrences. */
    val hbTokens: List<GsaTokenHeader>,
    /** `X-Apple-PE-Token` — the PET, 300 s default expiry when no trailer (§1.5). */
    val pet: GsaPet?,
)

/**
 * The §1.5 2FA browser-style header set (C59, values recorded): the anisette base headers
 * filtered to `X-Apple-I-MD-LU`/`X-Apple-I-MD-RINFO`/`X-Apple-I-MD-M`/`X-Apple-I-MD`/
 * `X-Mme-Device-Id` plus the recorded fixed literals and the flavor's app-name/bundle-id/
 * AK-context values.
 *
 * The two former TODO(capture) members are recorded literals now (§1.5 rev-15 closure): the
 * browser `User-Agent` defaults to [Companion.BROWSER_USER_AGENT], and the non-akd
 * `X-MMe-Client-Info` is the recorded device-bracket template built from [device]'s
 * device-dependent slots (null omits the header — the slots are caller configuration).
 */
class GsaTwoFactorHeaders(
    private val flavor: GsaFlavor,
    /** The filtered anisette set incl. the derived `X-Apple-I-MD-LU` — [GsaCpd.headersFor]. */
    private val anisette: Map<String, String>,
    /** Device slots of the recorded non-akd `X-MMe-Client-Info` template (§1.5); null omits the header. */
    val device: GsaHeaderConfig? = null,
    /** Browser `User-Agent` — the recorded literal is the default (§1.5). */
    val userAgent: String = BROWSER_USER_AGENT,
) {

    /** The recorded device-bracket form, or null when no device slots are configured. */
    val clientInfo: String?
        get() = device?.browserSetClientInfo

    fun toHeaders(): Map<String, String> = buildMap {
        putAll(anisette)
        put("X-Apple-Client-App-Name", flavor.clientAppName)
        put("X-Apple-I-Client-Bundle-Id", flavor.clientBundleId)
        clientInfo?.let { put("X-MMe-Client-Info", it) }
        put("X-Apple-I-CDP-Circle-Status", "false")
        put("X-Apple-I-ICSCREC", "true")
        put("User-Agent", userAgent)
        put("Sec-Fetch-Site", "same-origin")
        put("X-Apple-Requested-Partition", "0")
        put("X-Apple-I-DeviceUserMode", "0")
        put("X-Apple-I-Locale", "en_US")
        put("X-Apple-Security-Upgrade-Context", "com.apple.authkit.generic")
        put("Accept-Language", "en-US,en;q=0.9")
        put("X-Apple-I-PRK-Gen", "true")
        put("Sec-Fetch-Mode", "cors")
        put("X-Apple-I-TimeZone", "UTC")
        put("X-Apple-I-OT-Status", "false")
        put("X-Apple-I-TimeZone-Offset", "0")
        put("X-MMe-Country", "US")
        put("X-Apple-I-CDP-Status", "false")
        put("X-Apple-I-Device-Configuration-Mode", "0")
        put("Sec-Fetch-Dest", "empty")
        put("X-Apple-AK-Context-Type", flavor.akContextType)
        put("X-Apple-I-CFU-State", CFU_STATE)
    }

    companion object {
        /**
         * The decoded CFU-State wrapper, assembled from the recorded shape (§1.5). The recorded
         * decoded length is exactly 182 bytes, and the standard newline-after-each-element
         * Apple layout matches it byte-for-byte — pinned in [GsaTwoFactorTest].
         */
        val CFU_STATE_PLIST: String =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" " +
                "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" +
                "<plist version=\"1.0\">\n" +
                "<array/>\n" +
                "</plist>\n"

        /**
         * `X-Apple-I-CFU-State` (§1.5, C59): a hardcoded base64 whose decoded XML plist is the
         * FULL plist wrapper — prolog + Apple DOCTYPE + `<plist version="1.0">` + `<array/>` +
         * `</plist>` + trailing newline (182 bytes) — NOT a bare `<array/>`.
         */
        val CFU_STATE: String =
            java.util.Base64.getEncoder().encodeToString(CFU_STATE_PLIST.toByteArray(Charsets.UTF_8))

        /**
         * The recorded browser `User-Agent` literal (§1.5 rev-15 closure): static in every
         * source, notably with NO Safari/Version token.
         */
        const val BROWSER_USER_AGENT =
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)"

        fun of(
            cpd: GsaCpd,
            device: GsaHeaderConfig? = null,
            userAgent: String = BROWSER_USER_AGENT,
        ) = GsaTwoFactorHeaders(cpd.flavor, cpd.headersFor(), device, userAgent)
    }
}

/**
 * The §1.5 2FA paths.
 *
 * `secondaryAuth` (SMS/trusted phone): `GET .../auth` returns the `AuthenticationExtras` JSON
 * (HTTP 201 = SMS already sent); request a code with `PUT .../auth/verify/phone`; verify with
 * `POST .../auth/verify/phone/securitycode`.
 *
 * `trustedDeviceSecondaryAuth`: trigger the code push with `GET .../auth/verify/trusteddevice`,
 * then submit `GET .../GsService2/validate` with the code in a `security-code` request header.
 *
 * All requests carry `X-Apple-Identity-Token` (§1.5) and the recorded browser-style fixed
 * header set ([GsaTwoFactorHeaders], §1.5 C59); null omits it.
 *
 * No credential material (codes, tokens, identity token) is ever passed to [logEvent].
 */
class GsaTwoFactorClient(
    private val http: IdsHttp,
    private val browserHeaders: GsaTwoFactorHeaders? = null,
    private val authBase: String = "https://gsa.apple.com/auth",
    private val validateUrl: String = "https://gsa.apple.com/grandslam/GsService2/validate",
    private val trustedDeviceUrl: String = "https://gsa.apple.com/auth/verify/trusteddevice",
    private val logEvent: (String) -> Unit = {},
) {

    /**
     * `GET .../auth` — the trusted phone numbers. HTTP 200 parses the extras; HTTP 201 means
     * the SMS was already sent (§1.5); anything else fails loudly.
     */
    suspend fun trustedPhoneNumbers(identityToken: String): GsaAuthExtras {
        logEvent("gsa 2fa: authentication extras")
        val response = http.get(authBase, headers(identityToken))
        if (response.status != 200 && response.status != 201) {
            throw GsaLoginException("GSA auth extras GET $authBase → HTTP ${response.status} (§1.5)")
        }
        if (response.status == 201) logEvent("gsa 2fa: SMS already sent (HTTP 201)")
        val json = try {
            Json.parseToJsonElement(response.body.decodeToString())
        } catch (e: Exception) {
            throw GsaLoginException("GSA auth extras response is not JSON (§1.5): ${e.message}", e)
        }
        val numbers = json.jsonObject["trustedPhoneNumbers"]?.jsonArray ?: return GsaAuthExtras(emptyList())
        return GsaAuthExtras(numbers.map { entry ->
            val obj = entry.jsonObject
            GsaTrustedPhoneNumber(
                numberWithDialCode = obj["numberWithDialCode"].textOrNull(),
                lastTwoDigits = obj["lastTwoDigits"].textOrNull(),
                pushMode = obj["pushMode"].textOrNull()?.toBooleanStrictOrNull(),
                id = obj["id"].textOrNull()?.toLongOrNull(),
                raw = obj.mapValues { (_, value) -> value.textOrNull() },
            )
        })
    }

    /** `PUT .../auth/verify/phone` — request the SMS code for phone id [phoneNumberId]. */
    suspend fun requestSmsCode(identityToken: String, phoneNumberId: String) {
        logEvent("gsa 2fa: request SMS code")
        val response = http.put(
            "$authBase/verify/phone",
            headers(identityToken) + mapOf(CONTENT_TYPE_HEADER to JSON_CONTENT_TYPE),
            phoneBody(phoneNumberId).toString().toByteArray(Charsets.UTF_8),
            JSON_CONTENT_TYPE,
        )
        if (response.status != 200 && response.status != 201) {
            throw GsaLoginException("GSA SMS request PUT $authBase/verify/phone → HTTP ${response.status} (§1.5)")
        }
    }

    /** `POST .../auth/verify/phone/securitycode` — verify the SMS code; returns the token headers. */
    suspend fun submitSmsCode(
        identityToken: String,
        phoneNumberId: String,
        securityCode: String,
        nowEpochMs: Long,
    ): GsaSecondaryAuthTokens {
        logEvent("gsa 2fa: submit SMS code")
        val response = http.post(
            "$authBase/verify/phone/securitycode",
            headers(identityToken) + mapOf(CONTENT_TYPE_HEADER to JSON_CONTENT_TYPE),
            buildJsonObject {
                putJsonObject("phoneNumber") { put("id", phoneNumberId) }
                put("mode", "sms")
                putJsonObject("securityCode") { put("code", securityCode) }
            }.toString().toByteArray(Charsets.UTF_8),
            JSON_CONTENT_TYPE,
        )
        return tokensOf(response, nowEpochMs)
    }

    /** `GET .../auth/verify/trusteddevice` — push the code to the trusted devices. */
    suspend fun triggerTrustedDevice(identityToken: String) {
        logEvent("gsa 2fa: trigger trusted device")
        val response = http.get(trustedDeviceUrl, headers(identityToken))
        if (response.status != 200 && response.status != 201) {
            throw GsaLoginException(
                "GSA trusted-device trigger GET $trustedDeviceUrl → HTTP ${response.status} (§1.5)",
            )
        }
    }

    /** `GET .../GsService2/validate` with the code in the `security-code` header (§1.5). */
    suspend fun submitTrustedDeviceCode(
        identityToken: String,
        securityCode: String,
        nowEpochMs: Long,
    ): GsaSecondaryAuthTokens {
        logEvent("gsa 2fa: submit trusted device code")
        val response = http.get(validateUrl, headers(identityToken) + mapOf("security-code" to securityCode))
        return tokensOf(response, nowEpochMs)
    }

    private suspend fun tokensOf(response: IdsHttpResponse, nowEpochMs: Long): GsaSecondaryAuthTokens {
        if (response.status != 200 && response.status != 201) {
            throw GsaLoginException("GSA 2FA verification → HTTP ${response.status} (§1.5)")
        }
        return GsaSecondaryAuthTokens(
            gsTokens = GsaTokenHeaders.gsTokens(response.headers.header(HEADER_GS), nowEpochMs),
            hbTokens = response.headers.header(HEADER_HB)
                ?.let { GsaTokenHeaders.parse(HEADER_HB, it, nowEpochMs) } ?: emptyList(),
            pet = GsaTokenHeaders.pet(response.headers.header(HEADER_PE), nowEpochMs),
        )
    }

    private fun phoneBody(phoneNumberId: String) = buildJsonObject {
        putJsonObject("phoneNumber") { put("id", phoneNumberId) }
        put("mode", "sms")
    }

    private fun JsonElement?.textOrNull(): String? =
        (this as? JsonPrimitive)?.takeIf { it !is JsonNull }?.content

    /** §1.5: every 2FA request carries the identity token plus the recorded header set. */
    private fun headers(identityToken: String): Map<String, String> =
        (browserHeaders?.toHeaders() ?: emptyMap()) + mapOf(IDENTITY_TOKEN_HEADER to identityToken)

    private fun Map<String, String>.header(lowercasedName: String): String? =
        entries.firstOrNull { it.key.equals(lowercasedName, ignoreCase = true) }?.value

    companion object {
        const val IDENTITY_TOKEN_HEADER = "X-Apple-Identity-Token"
        const val CONTENT_TYPE_HEADER = "Content-Type"
        const val JSON_CONTENT_TYPE = "application/json"
        const val HEADER_GS = GsaTokenHeaders.HEADER_GS
        const val HEADER_HB = GsaTokenHeaders.HEADER_HB
        const val HEADER_PE = GsaTokenHeaders.HEADER_PE
    }
}
