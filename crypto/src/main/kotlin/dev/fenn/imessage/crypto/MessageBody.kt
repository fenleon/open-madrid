package dev.fenn.imessage.crypto

import dev.fenn.imessage.codec.NativePlist
import dev.fenn.imessage.codec.NativePlistException
import dev.fenn.imessage.codec.stringKeyedDictOrNull
import dev.fenn.imessage.codec.typeName

/**
 * The §5.2 normal message body — the decrypted inner plaintext of command
 * [PayloadCommands.PAYLOAD] (100), a string-keyed plist encoded with the `:codec` binary-plist bridge ([NativePlist]) and
 * optionally gzipped (§4.1) before encryption.
 *
 * Plist value types per body key are not recorded for most keys (§5.2; the value-type half
 * of C50 stays capture-bound, §7 item 17); the assumptions are stated on each property and
 * follow the spec's own quoting (versions quoted as strings: `gv` "8", `v` "1"). All fields
 * are optional: which subset a given message carries depends on the
 * message kind (plain text vs rich body vs balloon vs reaction target), and decode of a body
 * the spec does not fully describe must not fail on absent keys.
 */
data class MessageBody(
    /** `t` — plain text, the concatenation of parts. */
    val text: String? = null,
    /** `s` — subject. */
    val subject: String? = null,
    /** `p` — participants, full list including self, as URIs. */
    val participants: List<String>? = null,
    /** `x` — rich XML body (present when multipart, mentions, or styling). */
    val richBody: String? = null,
    /** `gid` — group GUID. */
    val groupGuid: String? = null,
    /** `gv` — group version, "8". */
    val groupVersion: String? = null,
    /** `v` — protocol version, "1". */
    val protocolVersion: String? = null,
    /** `pv` — properties version (0 for DMs, 1 for groups per one source). */
    val propertiesVersion: Long? = null,
    /** `tg` — reply/thread reference, format "r:<part>:<start>:<length>:<UUID>". */
    val threadRef: String? = null,
    /** `iid` — screen-effect id ("com.apple.messages.effect.*" / "com.apple.MobileSMS.expressivesend.*"). */
    val screenEffect: String? = null,
    /** `n` — chat display name. */
    val displayName: String? = null,
    /** `a` — audio flag (modeled as a boolean; type not captured, C50). */
    val audio: Boolean? = null,
    /** `e` — expiring-audio flag (modeled as a boolean; type not captured, C50). */
    val expiringAudio: Boolean? = null,
    /** `bid` — balloon id. */
    val balloonId: String? = null,
    /** `bp` — balloon payload (optionally gzipped; raw keyed-archiver plist or a wrapper). */
    val balloonPayload: ByteArray? = null,
    /** `bpdi` — balloon MMCS download info (key, size, owner, URL, signature). */
    val balloonDownloadInfo: Map<String, Any?>? = null,
    /** `msi` — message-summary info (content-type number `amc`, source text `ams`, balloon type `amb`). */
    val messageSummaryInfo: Map<String, Any?>? = null,
    /** `r` — previous-message UUID (modeled as 16 UUID bytes; type not captured, C50). */
    val previousMessageUuid: ByteArray? = null,
) {

    fun encode(): ByteArray = NativePlist.encode(toMap())

    fun toMap(): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        text?.let { m["t"] = it }
        subject?.let { m["s"] = it }
        participants?.let { m["p"] = it }
        richBody?.let { m["x"] = it }
        groupGuid?.let { m["gid"] = it }
        groupVersion?.let { m["gv"] = it }
        protocolVersion?.let { m["v"] = it }
        propertiesVersion?.let { m["pv"] = it }
        threadRef?.let { m["tg"] = it }
        screenEffect?.let { m["iid"] = it }
        displayName?.let { m["n"] = it }
        audio?.let { m["a"] = it }
        expiringAudio?.let { m["e"] = it }
        balloonId?.let { m["bid"] = it }
        balloonPayload?.let { m["bp"] = it }
        balloonDownloadInfo?.let { m["bpdi"] = it }
        messageSummaryInfo?.let { m["msi"] = it }
        previousMessageUuid?.let { m["r"] = it }
        return m
    }

    companion object {

        /** Decodes a command-100 body; recorded-but-absent keys stay null. */
        fun decode(bytes: ByteArray): MessageBody {
            val dict = NativePlist.decode(bytes)
            val m = stringKeyedDictOrNull(dict)
                ?: throw NativePlistException("message body is not a string-keyed dict (${typeName(dict)})")
            fun str(key: String): String? = m[key] as? String
            fun long(key: String): Long? = (m[key] as? Int)?.toLong() ?: m[key] as? Long
            fun bool(key: String): Boolean? = m[key] as? Boolean
            fun data(key: String): ByteArray? = m[key] as? ByteArray
            fun dict(key: String): Map<String, Any?>? = stringKeyedDictOrNull(m[key])
            fun strList(key: String): List<String>? = (m[key] as? List<*>)?.map {
                it as? String ?: throw NativePlistException("'$key' element is not a string (${typeName(it)})")
            }
            return MessageBody(
                text = str("t"),
                subject = str("s"),
                participants = strList("p"),
                richBody = str("x"),
                groupGuid = str("gid"),
                groupVersion = str("gv"),
                protocolVersion = str("v"),
                propertiesVersion = long("pv"),
                threadRef = str("tg"),
                screenEffect = str("iid"),
                displayName = str("n"),
                audio = bool("a"),
                expiringAudio = bool("e"),
                balloonId = str("bid"),
                balloonPayload = data("bp"),
                balloonDownloadInfo = dict("bpdi"),
                messageSummaryInfo = dict("msi"),
                previousMessageUuid = data("r"),
            )
        }
    }
}
