package dev.fenn.imessage.ids

import dev.fenn.imessage.codec.BplistFormatException
import dev.fenn.imessage.codec.NativePlist
import dev.fenn.imessage.codec.Plist
import dev.fenn.imessage.codec.PlistFormatException
import dev.fenn.imessage.codec.stringKeyedDictOrNull
import dev.fenn.imessage.codec.typeName
import java.util.concurrent.ConcurrentHashMap

/** Bag fetch/parse/HTTP failure (spec §1.2). */
class IdsBagException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * A key inside a parsed bag that the bag does not carry. Spec §1.2: "a missing key inside the
 * parsed bag is its own error" — there is no pinned-URL fallback for a vanished bag key.
 */
class BagKeyMissingException(val key: String) : Exception("bag has no key '$key'")

/** A fetched bag as a flat bag-key → value dictionary (spec §1.2). */
class Bag(entries: Map<String, Any?>) {

    val raw: Map<String, Any?> = entries

    fun string(key: String): String {
        val value = existing(key)
        return value as? String ?: throw IdsBagException("bag key '$key' is ${typeName(value)}, not a string")
    }

    /** Same as [string], for keys the spec §1.2 lists as endpoint URLs. */
    fun url(key: String): String = string(key)

    fun long(key: String): Long {
        val value = existing(key)
        return when (value) {
            is Long -> value
            is Int -> value.toLong()
            else -> throw IdsBagException("bag key '$key' is ${typeName(value)}, not an integer")
        }
    }

    private fun existing(key: String): Any? =
        if (raw.containsKey(key)) raw[key] else throw BagKeyMissingException(key)
}

/** `APNSCourierHostname`/`APNSCourierHostcount` from the APNs bag (spec §3.1) — feeds the courier client config. */
data class CourierEndpoint(val hostname: String, val hostCount: Int)

/**
 * Bag fetchers per spec §1.2.
 *
 * Caching is exactly what the spec states: process-lifetime, keyed by bag URL, no TTL and no
 * refresh — keep one fetcher for the process. Two concurrent first calls can each fetch (the
 * result is identical either way); a lock would serialize unrelated callers, so there is none.
 *
 * [plistParser] is the plist seam; the default is the `:codec` format-dispatching
 * [Plist.parse] (binary + XML — [CAP-BAGCT] observes XML on the bag wire).
 */
class IdsBagFetcher(
    private val http: IdsHttp,
    val idsBagUrl: String = IDS_BAG_URL,
    val apnsBagUrl: String = APNS_BAG_URL,
    private val plistParser: (ByteArray) -> Any? = { Plist.parse(it) },
) {

    private val cache = ConcurrentHashMap<String, Bag>()

    /** The IDS bag. Spec §1.2 [CAP-BAG]: an unauthenticated GET; the response is a plist with `signature`, `certs` and `bag`. */
    suspend fun idsBag(): Bag = cache[idsBagUrl] ?: fetchDict(idsBagUrl).also { cache[idsBagUrl] = it }

    /** The APNs bag, fetched over **plain HTTP** (spec §1.2). */
    suspend fun apnsBag(): Bag = cache[apnsBagUrl] ?: fetchDict(apnsBagUrl).also { cache[apnsBagUrl] = it }

    /** Courier hostname/count for the courier client config (spec §3.1). */
    suspend fun courierEndpoint(): CourierEndpoint {
        val bag = apnsBag()
        return CourierEndpoint(
            hostname = bag.string("APNSCourierHostname"),
            hostCount = bag.long("APNSCourierHostcount").toInt(),
        )
    }

    private suspend fun fetchDict(url: String): Bag {
        val response = http.get(url)
        if (response.status != 200) throw IdsBagException("GET $url → HTTP ${response.status}")
        return Bag(flatDict(response.body, url))
    }

    /**
     * Spec §1.2 records the nested shape for the IDS bag: the dict's `bag` value is embedded
     * plist data that is itself parsed into the flat dictionary. The APNs bag's outer shape is
     * not recorded (TODO(capture) C47), so a response that is already the flat dict is accepted
     * too — a wrong reading still fails loudly on the key lookup in [courierEndpoint].
     */
    private fun flatDict(body: ByteArray, url: String): Map<String, Any?> {
        val outer = parseDict(body, url)
        val embedded = outer["bag"] ?: return outer
        return when (embedded) {
            is ByteArray -> parseDict(embedded, "$url embedded 'bag'")
            is Map<*, *> -> stringKeyedDictOrNull(embedded)
                ?: throw IdsBagException("$url embedded 'bag' is not a string-keyed dict")
            else -> throw IdsBagException("$url 'bag' is ${typeName(embedded)}, expected data or dict")
        }
    }

    private fun parseDict(body: ByteArray, url: String): Map<String, Any?> {
        val parsed = try {
            plistParser(body)
        } catch (e: PlistFormatException) {
            throw IdsBagException("$url is not a plist: ${e.message}", e)
        }
        return stringKeyedDictOrNull(parsed) ?: throw IdsBagException("$url is ${typeName(parsed)}, expected a dict")
    }

    companion object {
        const val IDS_BAG_URL = "https://init.ess.apple.com/WebObjects/VCInit.woa/wa/getBag?ix=3"
        const val APNS_BAG_URL = "http://init-p01st.push.apple.com/bag"
    }
}
