package dev.fenn.imessage.codec

/**
 * Bridge between the binary-plist [BpValue] tree and plain Kotlin values (Long, String,
 * Boolean, Double, ByteArray, List, Map) — the shape the plist consumers in this repo work
 * with. Binary plists only: this codec does not parse XML plists.
 */
class NativePlistException(message: String, cause: Throwable? = null) : Exception(message, cause)

object NativePlist {

    /** Encodes a tree of plain Kotlin values as a binary plist. */
    fun encode(dict: Map<String, Any?>): ByteArray = Bplist.encode(fromNative(dict))

    /** Decodes a binary plist into plain Kotlin values. */
    fun decode(bytes: ByteArray): Any? = toNative(Bplist.decode(bytes))

    /** Converts a [BpValue] tree into plain Kotlin values (see [decode]). */
    fun toNative(value: BpValue): Any? = when (value) {
        is BpNull -> null
        is BpBool -> value.value
        is BpInt -> value.value
        is BpReal -> value.value
        is BpDate -> PlistDate(
            (PlistDate.APPLE_EPOCH_MILLIS + value.secondsSince2001 * 1000).let { Math.round(it) },
        )
        is BpData -> value.bytes
        is BpString -> value.value
        is BpUid -> value.value
        is BpArray -> value.items.map { toNative(it) }
        is BpDict -> LinkedHashMap<Any?, Any?>(value.entries.size).apply {
            value.entries.forEach { (k, v) -> put(toNative(k), toNative(v)) }
        }
    }

    /** Converts plain Kotlin values into the [BpValue] tree. */
    fun fromNative(value: Any?): BpValue = when (value) {
        null -> BpNull
        is BpValue -> value
        is PlistDate -> BpDate((value.epochMillis - PlistDate.APPLE_EPOCH_MILLIS) / 1000.0)
        is String -> BpString(value)
        is Boolean -> BpBool(value)
        is Int -> BpInt(value.toLong())
        is Long -> BpInt(value)
        is Double -> BpReal(value)
        is Float -> BpReal(value.toDouble())
        is ByteArray -> BpData(value)
        is List<*> -> BpArray(value.map { fromNative(it) })
        is Map<*, *> -> BpDict(LinkedHashMap<BpValue, BpValue>(value.size).apply {
            value.forEach { (k, v) -> put(fromNative(k), fromNative(v)) }
        })
        else -> throw NativePlistException("no plist representation for ${value::class.java.name}")
    }
}

/** The [value] as a string-keyed dict, or null when it is not one. */
fun stringKeyedDictOrNull(value: Any?): Map<String, Any?>? =
    (value as? Map<*, *>)?.takeIf { map -> map.keys.all { it is String } }
        ?.mapKeys { it.key as String }

/** A decoded plist integer — the codecs decode to Long, hand-built dicts may hold Int. */
fun integerOrNull(value: Any?): Int? = when (value) {
    is Long -> value.toInt()
    is Int -> value
    else -> null
}

fun longOrNull(value: Any?): Long? = when (value) {
    is Long -> value
    is Int -> value.toLong()
    else -> null
 }

/** A human-readable type name for parse-error messages ("a string", "a dict", …). */
fun typeName(value: Any?): String = when (value) {
    null -> "null"
    is String -> "a string"
    is Boolean -> "a boolean"
    is Int, is Long -> "an integer"
    is Double, is Float -> "a real"
    is ByteArray -> "data"
    is List<*> -> "an array"
    is Map<*, *> -> "a dict"
    else -> value::class.java.simpleName
}
