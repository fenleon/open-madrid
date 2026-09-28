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
 * One token parsed out of a §1.5 response header (`X-Apple-GS-Token`, `X-Apple-HB-Token`,
 * `X-Apple-PE-Token`): each is base64 of colon-separated `ID:TOKEN[:DURATION][:EXP]` with
 * inconsistent duration/expiration trailer forms (epoch-ms vs seconds, heuristically parsed).
 */
data class GsaTokenHeader(
    /** The leading service id before the first colon. */
    val serviceId: String,
    /** The token itself (the second field). */
    val token: String,
    /** The `DURATION` trailer in seconds, when a two-trailer form carries one. */
    val durationSeconds: Long?,
    /**
     * The expiration, epoch ms: the `EXP` trailer when present, else the single trailer.
     * Heuristic (§1.5 "heuristically parsed"): a trailer ≥ 10^11 is epoch-ms, below it is
     * epoch-seconds and is scaled to ms.
     */
    val expiresAtEpochMs: Long?,
)

/**
 * Parser for the §1.5 response-header token sets. Repeated headers arrive as comma-joined
 * values ([AppleIdsHttp] joins them with ", "); base64 payloads contain neither commas nor
 * colons, so splitting on the comma first is safe.
 *
 * Field grammar (§1.5): `ID:TOKEN[:DURATION][:EXP]`. A single trailer is read as the
 * expiration (the PET recording — "default expiry 300 s when no trailer, otherwise parsed
 * seconds/epoch-ms" — describes the trailer as the expiry); two trailers are DURATION then
 * EXP. A non-numeric trailer is surfaced as null rather than failing — the trailer forms are
 * recorded as inconsistent — but an `ID:TOKEN` shape is required or the value fails loudly.
 */
object GsaTokenHeaders {

    /** One token is parsed per header occurrence; [headerValue] may hold comma-joined repeats. */
    fun parse(headerName: String, headerValue: String, nowEpochMs: Long): List<GsaTokenHeader> =
        headerValue.split(',').mapNotNull { occurrence -> parseOne(headerName, occurrence.trim(), nowEpochMs) }

    private fun parseOne(headerName: String, value: String, nowEpochMs: Long): GsaTokenHeader? {
        if (value.isEmpty()) return null
        val decoded = try {
            String(Base64.getMimeDecoder().decode(value), Charsets.UTF_8)
        } catch (e: IllegalArgumentException) {
            throw GsaLoginException("$headerName is not decodable base64 (spec §1.5 token header)", e)
        }
        val fields = decoded.split(':')
        if (fields.size < 2) {
            throw GsaLoginException("$headerName payload '$decoded' is not the recorded ID:TOKEN shape (§1.5)")
        }
        val trailers = fields.drop(2).map { it.trim() }.filter { it.isNotEmpty() }
        return when (trailers.size) {
            0 -> GsaTokenHeader(fields[0], fields[1], durationSeconds = null, expiresAtEpochMs = null)
            1 -> GsaTokenHeader(
                fields[0], fields[1],
                durationSeconds = null,
                expiresAtEpochMs = trailers[0].toLongOrNull()?.asExpiry(),
            )
            else -> GsaTokenHeader(
                fields[0], fields[1],
                durationSeconds = trailers[0].toLongOrNull(),
                expiresAtEpochMs = trailers[1].toLongOrNull()?.asExpiry(),
            )
        }
    }

    private fun Long.asExpiry(): Long = if (this >= EPOCH_MS_THRESHOLD) this else this * 1000

    /** Above this, a trailer can only be epoch-ms (epoch-seconds stay below 10^10). */
    const val EPOCH_MS_THRESHOLD = 100_000_000_000L

    /** The §1.5 PET default: 300 s when the header carries no trailer. */
    const val PET_DEFAULT_EXPIRY_SECONDS = 300L

    /**
     * The PET entry from a token-header set, with its expiry: the trailer when present,
     * otherwise now + the recorded 300 s default (§1.5).
     */
    fun pet(headerValue: String?, nowEpochMs: Long): GsaPet? {
        val parsed = headerValue?.let { parse(HEADER_PE, it, nowEpochMs) } ?: return null
        val first = parsed.firstOrNull() ?: return null
        return GsaPet(
            token = first.token,
            expiresAtEpochMs = first.expiresAtEpochMs ?: nowEpochMs + PET_DEFAULT_EXPIRY_SECONDS * 1000,
        )
    }

    /** Every token in a comma-joined [X-Apple-GS-Token] value, keyed by service id. */
    fun gsTokens(headerValue: String?, nowEpochMs: Long): Map<String, GsaTokenHeader> {
        val parsed = headerValue?.let { parse(HEADER_GS, it, nowEpochMs) } ?: return emptyMap()
        return parsed.associateBy { it.serviceId }
    }

    const val HEADER_GS = "X-Apple-GS-Token"
    const val HEADER_HB = "X-Apple-HB-Token"
    const val HEADER_PE = "X-Apple-PE-Token"
}

/** The Password Equivalent Token (§1.5): the Basic password on the iCloud requests. */
data class GsaPet(
    val token: String,
    val expiresAtEpochMs: Long,
)
