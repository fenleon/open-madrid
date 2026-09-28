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

/** Anisette header assembly failure (a seam produced no value where one is required). */
class AnisetteException(message: String) : Exception(message)

/**
 * The §1.1 hardware-configuration field set (one struct for both consumers): the three
 * hardware anisette headers the header provider encodes, plus the full identifier set the
 * Mac-Hardware-Info export code carries (parsed by chunk B2's [MacHardwareInfoExportCode]).
 *
 * The export-only fields default to null — [AnisetteHeaderProvider] consumes only the three
 * header values; the parser fills the whole struct.
 */
data class MacHardwareIdentifiers(
    /** `X-Apple-I-SRL-NO` — the platform serial. */
    val serialNumber: String,
    /** `X-Apple-I-MLB` — the logic-board serial. */
    val logicBoardSerial: String,
    /** `X-Apple-I-ROM` raw bytes — encoded lowercase hex on the wire (§1.1). */
    val rom: ByteArray,
    /** Apple product-type form, e.g. `Macmini9,1` (§1.1). */
    val productName: String? = null,
    /** The MAC address — exactly 6 raw bytes (§1.1). */
    val macAddress: ByteArray? = null,
    /** The platform UUID. */
    val platformUuid: String? = null,
    /** The root-disk UUID. */
    val rootDiskUuid: String? = null,
    /** The board ID, e.g. `Mac-…` (§1.1). */
    val boardId: String? = null,
    /** The OS build number (§1.1). */
    val osBuildNumber: String? = null,
    /** The five `_enc` obfuscated raw-byte variants, §1.1 label mapping. */
    val serialEnc: ByteArray? = null,
    val platformUuidEnc: ByteArray? = null,
    val rootDiskUuidEnc: ByteArray? = null,
    val romEnc: ByteArray? = null,
    val mlbEnc: ByteArray? = null,
)

/**
 * The capture-bound anisette values the spec names but does not give forms for
 * (TODO(capture) C6): the `X-Apple-I-Client-Time` format, the `X-Apple-I-TimeZone`,
 * `X-Apple-Locale`, and `X-Apple-I-MD-RINFO` values, and the `X-Mme-Device-Id` value
 * form. All caller-supplied — nothing here is invented.
 */
class AnisetteValueFormats(
    /** Formats the request time (epoch ms) into the `X-Apple-I-Client-Time` wire value. */
    val clientTime: (nowEpochMs: Long) -> String,
    /** The `X-Apple-I-TimeZone` value. */
    val timeZone: String,
    /** The `X-Apple-Locale` value. */
    val locale: String,
    /** The `X-Apple-I-MD-RINFO` value. */
    val rinfo: String,
    /** The `X-Mme-Device-Id` value (form unrecorded). */
    val deviceId: String,
)

/** The inputs of the local OTP derivation: machine state plus a one-time identifier (§1.1). */
class AnisetteOtpInput(
    /** The machine identifier — the same bytes [AnisetteHeaderProvider] base64s into `X-Apple-I-MD-M`. */
    val machineIdentifier: ByteArray,
    /** The one-time identifier of this OTP request (provenance unrecorded — caller-supplied). */
    val oneTimeIdentifier: ByteArray,
)

/**
 * The local OTP derivation seam (§1.1: ADI provisioning yields machine tokens, "then a local
 * OTP"). The derivation algorithm is not recorded — TODO(capture) C6 — so this stays injectable:
 * production supplies the real derivation once the capture names it; tests supply known answers.
 * The output is the raw OTP bytes (the provider base64s them into `X-Apple-I-MD`).
 */
fun interface AnisetteOtp {
    fun otp(input: AnisetteOtpInput): ByteArray
}

/**
 * The per-request anisette header set of spec §1.1 (C6 header-set half, closed by
 * facts-only extraction) — exactly the seven recorded headers:
 *
 * `X-Apple-I-Client-Time`, `X-Apple-I-TimeZone`, `X-Apple-Locale`, `X-Apple-I-MD-RINFO`,
 * `X-Mme-Device-Id`, `X-Apple-I-MD` (base64 OTP), `X-Apple-I-MD-M` (base64 machine ID),
 *
 * plus the macOS hardware headers when [MacHardwareIdentifiers] is supplied:
 * `X-Apple-I-MLB`, `X-Apple-I-ROM` (lowercase hex), `X-Apple-I-SRL-NO`.
 *
 * The machine identifier's provenance is the ADI provisioning machine tokens (§1.1) — its
 * wire form is unrecorded (TODO(capture) C6), so it arrives as raw caller-supplied bytes.
 */
class AnisetteHeaderProvider(
    private val machineIdentifier: ByteArray,
    private val macHardware: MacHardwareIdentifiers?,
    private val otp: AnisetteOtp,
    private val formats: AnisetteValueFormats,
) {

    /**
     * The header map, in the §1.1 recording order. [nowEpochMs] feeds the client-time format;
     * [oneTimeIdentifier] feeds the OTP seam. An OTP seam that returns no bytes fails loudly —
     * an absent `X-Apple-I-MD` is never silently sent.
     */
    fun headers(nowEpochMs: Long, oneTimeIdentifier: ByteArray): Map<String, String> {
        val otpBytes = otp.otp(AnisetteOtpInput(machineIdentifier, oneTimeIdentifier))
        if (otpBytes.isEmpty()) throw AnisetteException("OTP seam returned no bytes for X-Apple-I-MD")
        val out = LinkedHashMap<String, String>()
        out[CLIENT_TIME] = formats.clientTime(nowEpochMs)
        out[TIME_ZONE] = formats.timeZone
        out[LOCALE] = formats.locale
        out[RINFO] = formats.rinfo
        out[DEVICE_ID] = formats.deviceId
        out[MACHINE_OTP] = base64(otpBytes)
        out[MACHINE_ID] = base64(machineIdentifier)
        macHardware?.let {
            out[MAC_MLB] = it.logicBoardSerial
            out[MAC_ROM] = it.rom.joinToString("") { byte -> "%02x".format(byte) }
            out[MAC_SRL_NO] = it.serialNumber
        }
        return out
    }

    private fun base64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    companion object {
        /** Recorded wire names (spec §1.1) — pinned here and in [AnisetteHeadersTest]. */
        const val CLIENT_TIME = "X-Apple-I-Client-Time"
        const val TIME_ZONE = "X-Apple-I-TimeZone"
        const val LOCALE = "X-Apple-Locale"
        const val RINFO = "X-Apple-I-MD-RINFO"
        const val DEVICE_ID = "X-Mme-Device-Id"
        const val MACHINE_OTP = "X-Apple-I-MD"
        const val MACHINE_ID = "X-Apple-I-MD-M"
        const val MAC_MLB = "X-Apple-I-MLB"
        const val MAC_ROM = "X-Apple-I-ROM"
        const val MAC_SRL_NO = "X-Apple-I-SRL-NO"
    }
}
