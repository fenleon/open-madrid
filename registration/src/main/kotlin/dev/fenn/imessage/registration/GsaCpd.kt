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
/**
 * The GSA flavor of spec §1.5 (C59): which client identity the login impersonates. Recorded
 * per-flavor cpd/header values — Messages: `capp` = `Messages`, `cbid` = `com.apple.MobileSMS`,
 * `svct`/`X-Apple-AK-Context-Type` = `imessage`; AppleIDSettings: `icloud` /
 * `com.apple.systempreferences.AppleIDSettings` / `icloud`.
 */
enum class GsaFlavor(
    /** `capp` / `X-Apple-Client-App-Name`. */
    val clientAppName: String,
    /** `cbid` / `X-Apple-I-Client-Bundle-Id`. */
    val clientBundleId: String,
    /** `svct` / `X-Apple-AK-Context-Type`. */
    val akContextType: String,
) {
    MESSAGES("Messages", "com.apple.MobileSMS", "imessage"),
    APPLE_ID_SETTINGS("icloud", "com.apple.systempreferences.AppleIDSettings", "icloud"),
}

/**
 * The GSA `cpd` (client-provided-data) dictionary of spec §1.5 — a dict inside the request
 * body carrying the anisette values as KEYS plus the fixed-value set. Anisette values come
 * from chunk A's [AnisetteHeaderProvider]; the `X-Apple-I-MD-LU` value is derived here from
 * the keychain identifier per §1.1 (lowercase hex SHA-256 over the same 16 bytes).
 *
 * `capp`/`cbid`/`svct` ride the recorded per-flavor values ([GsaFlavor], C59); `ptkn` (APNs
 * token) is optional.
 *
 * Recorded fixed values, pinned: `X-Apple-I-Device-Configuration-Mode` = `0`,
 * `X-Apple-I-Request-UUID` (uppercase UUIDv4 — one per login, reused across both steps,
 * passed in), `X-Apple-Requested-Partition` = `0`,
 * `X-Apple-Security-Upgrade-Context` = `com.apple.authkit.generic`, `cou` = `US`,
 * `loc` = `en_US`, and the booleans `X-Apple-Offer-Security-Upgrade`=true, `bootstrap`=true,
 * `ckgen`=true, `fcd`=true, `icdrsDisabled`=false, `icscrec`=true, `pbe`=false,
 * `prkgen`=true, `webAccessEnabled`=false, `at`=0 (the spec lists `at` among the booleans
 * but records its value as `0`; encoded as the plist boolean false).
 */
class GsaCpd(
    /** The §1.1 anisette headers (from [AnisetteHeaderProvider.headers]). */
    private val anisette: Map<String, String>,
    /** The 16-byte keychain identifier — feeds the `X-Apple-I-MD-LU` derivation (§1.1). */
    private val keychainIdentifier: ByteArray,
    /** The recorded per-flavor `capp`/`cbid`/`svct` values (§1.5, C59). */
    val flavor: GsaFlavor = GsaFlavor.MESSAGES,
    /** Optional APNs token (`ptkn`). */
    private val apnsToken: String? = null,
) {

    /** The cpd dict for one login; [requestUuid] is the uppercase UUIDv4 shared by both steps. */
    fun dictFor(requestUuid: String): Map<String, Any?> {
        val dict = LinkedHashMap<String, Any?>()
        ANISETTE_KEYS.forEach { key -> anisette[key]?.let { dict[key] = it } }
        dict["X-Apple-I-MD-LU"] = mdLu()
        dict["X-Apple-I-Device-Configuration-Mode"] = "0"
        dict[REQUEST_UUID_KEY] = requestUuid
        dict["X-Apple-Requested-Partition"] = "0"
        dict["X-Apple-Security-Upgrade-Context"] = SECURITY_UPGRADE_CONTEXT
        dict["capp"] = flavor.clientAppName
        dict["cbid"] = flavor.clientBundleId
        dict["cou"] = "US"
        dict["loc"] = "en_US"
        dict["svct"] = flavor.akContextType
        dict["X-Apple-Offer-Security-Upgrade"] = true
        dict["at"] = false
        dict["bootstrap"] = true
        dict["ckgen"] = true
        dict["fcd"] = true
        dict["icdrsDisabled"] = false
        dict["icscrec"] = true
        dict["pbe"] = false
        dict["prkgen"] = true
        dict["webAccessEnabled"] = false
        apnsToken?.let { dict["ptkn"] = it }
        return dict
    }

    /** §1.1: lowercase hex (no dashes) SHA-256 over the 16-byte keychain identifier. */
    private fun mdLu(): String = java.security.MessageDigest.getInstance("SHA-256")
        .digest(keychainIdentifier)
        .joinToString("") { "%02x".format(it) }

    /**
     * The §1.5 header set that rides the GSA POSTs: the base anisette headers filtered to
     * `X-Apple-I-MD-LU`, `X-Apple-I-MD-RINFO`, `X-Apple-I-MD-M`, `X-Apple-I-MD`,
     * `X-Mme-Device-Id` — the same values the cpd carries, as headers. The akd-variant
     * headers ([GsaHeaderConfig]) are appended by the caller.
     */
    fun headersFor(): Map<String, String> = buildMap {
        anisette[AnisetteHeaderProvider.MACHINE_OTP]?.let { put(AnisetteHeaderProvider.MACHINE_OTP, it) }
        anisette[AnisetteHeaderProvider.RINFO]?.let { put(AnisetteHeaderProvider.RINFO, it) }
        anisette[AnisetteHeaderProvider.MACHINE_ID]?.let { put(AnisetteHeaderProvider.MACHINE_ID, it) }
        anisette[AnisetteHeaderProvider.DEVICE_ID]?.let { put(AnisetteHeaderProvider.DEVICE_ID, it) }
        put("X-Apple-I-MD-LU", mdLu())
    }

    companion object {
        /** The anisette header names the §1.5 cpd carries as keys (values from the provider). */
        val ANISETTE_KEYS = listOf(
            AnisetteHeaderProvider.CLIENT_TIME,
            AnisetteHeaderProvider.MACHINE_OTP,
            AnisetteHeaderProvider.RINFO,
            AnisetteHeaderProvider.MACHINE_ID,
            AnisetteHeaderProvider.DEVICE_ID,
        )

        const val SECURITY_UPGRADE_CONTEXT = "com.apple.authkit.generic"
        const val REQUEST_UUID_KEY = "X-Apple-I-Request-UUID"
    }
}

/**
 * The §1.5 akd-variant headers of the GSA POSTs (C59, values recorded): the akd
 * `User-Agent` literal, the akd-form `X-MMe-Client-Info` template with the device-dependent
 * parts (hardware model, OS name/version/build) as configuration, and the flavor's
 * `X-Apple-AK-Context-Type`/`X-Apple-Client-App-Name`/`X-Apple-I-Client-Bundle-Id` values.
 */
data class GsaHeaderConfig(
    val flavor: GsaFlavor = GsaFlavor.MESSAGES,
    /** The `<HardwareModel>` slot of the akd `X-MMe-Client-Info` template (§1.5, device-dependent). */
    val hardwareModel: String,
    /** The `<OSname>` slot (§1.5, device-dependent), e.g. `macOS` / `iPhone OS`. */
    val osName: String,
    /** The `<OSversion>` slot (§1.5, device-dependent). */
    val osVersion: String,
    /** The `<OSbuild>` slot (§1.5, device-dependent). */
    val osBuild: String,
) {

    /** The akd-form template: `<HardwareModel> <OSname;OSversion;OSbuild> <com.apple.AuthKit/1 (com.apple.akd/1.0)>`. */
    val clientInfo: String
        get() = "<$hardwareModel> <${osName};${osVersion};${osBuild}> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"

    /**
     * The recorded non-akd browser-set `X-MMe-Client-Info` (§1.5 rev-15 closure): the same
     * device-bracket form with the fixed inner component `com.apple.akd/1.0 (com.apple.akd/1.0)`.
     */
    val browserSetClientInfo: String
        get() = "<$hardwareModel> <${osName};${osVersion};${osBuild}> <com.apple.akd/1.0 (com.apple.akd/1.0)>"

    /**
     * The recorded bracketed sign-in `X-Mme-Client-Info` (§1.5 rev-15 closure): the device-bracket
     * form wrapping the recorded AOSKit inner component ([GsaDelegateLoginClient.AOSKIT_CLIENT_INFO]).
     */
    val signInClientInfo: String
        get() = "<$hardwareModel> <${osName};${osVersion};${osBuild}> <$AOSKIT_CLIENT_INFO>"

    fun toHeaders(): Map<String, String> = linkedMapOf(
        "X-MMe-Client-Info" to clientInfo,
        "User-Agent" to AKD_USER_AGENT,
        "X-Apple-AK-Context-Type" to flavor.akContextType,
        "X-Apple-Client-App-Name" to flavor.clientAppName,
        "X-Apple-I-Client-Bundle-Id" to flavor.clientBundleId,
    )

    companion object {
        /** The recorded akd `User-Agent` literal (§1.5, C59). */
        const val AKD_USER_AGENT = "akd/1.0 CFNetwork/1494.0.7 Darwin/23.4.0"

        /** The recorded AOSKit inner component (§1.5, C59) — wrapped by [signInClientInfo]. */
        const val AOSKIT_CLIENT_INFO = "com.apple.AOSKit/282 (com.apple.accountsd/113)"
    }
}
