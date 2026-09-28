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
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Mac-Hardware-Info export-code parse failure (spec §1.1, C58). */
class MacHardwareInfoExportException(message: String, cause: Throwable? = null) :
    Exception(message, cause)

/**
 * One parsed Mac-Hardware-Info export code (spec §1.1, C58): the `OABS` payload — flag byte,
 * outer protobuf fields, and the nested identifier message as the §1.1 hardware-configuration
 * struct ([MacHardwareIdentifiers]).
 */
class MacHardwareInfoExport(
    /** The one-byte flag: true = "prevent sharing" mode (§1.1). */
    val preventSharing: Boolean,
    /** Outer field 2 — the macOS product version (sysctl `kern.osproductversion`). */
    val macOsProductVersion: String?,
    /** Outer field 3 — the protocol version (hardcoded [MacHardwareInfoExportCode.PROTOCOL_VERSION]). */
    val protocolVersion: Long?,
    /** Outer field 4 — the device id (the IOPlatformUUID again). */
    val deviceId: String?,
    /** Outer field 5 — the hardcoded iCloudHelper user-agent string. */
    val icloudHelperUserAgent: String?,
    /** Outer field 6 — the hardcoded AOSKit version string. */
    val aosKitVersion: String?,
    /** The nested identifier message (outer field 1) — required, fails loudly when absent. */
    val identifiers: MacHardwareIdentifiers,
)

/**
 * The Mac-Hardware-Info export-code parser (spec §1.1, C58 — the parse specification; the
 * helper itself is closed source and unlicensed upstream — facts only).
 *
 * Wire format: 4-byte ASCII magic `OABS`, one flag byte (1 = prevent sharing), then a raw
 * protobuf message (no length prefix) starting at offset 5. Outer fields: 1 nested identifier
 * message, 2 macOS product version, 3 protocol version (varint), 4 device id, 5
 * iCloudHelper user-agent, 6 AOSKit version. Nested identifier fields: 1 product name,
 * 2 MAC address (6 raw bytes), 3 platform serial, 4 platform UUID, 5 root-disk UUID,
 * 6 board ID, 7 OS build number, 8/9/10/12/14 the five `_enc` blobs, 11 ROM, 13 MLB.
 *
 * Two delivery modes: plain = standard base64 of the payload (clipboard text, or the raw
 * payload bytes as a QR code); restricted = OpenSSL-`Salted__` AES-256-CBC/PKCS7 container
 * keyed by the human activation code (legacy EVP_BytesToKey: repeated MD5 of previous-hash ‖
 * password ‖ salt to 48 bytes — first 32 = key, next 16 = IV), then base64. [parse] accepts
 * either base64 text, [parsePayload] the raw payload bytes (the QR path).
 *
 * The decoder is hand-rolled and tolerant: singular fields (last one wins), UTF-8 strings,
 * raw bytes, unknown fields skipped; a wrong magic or a missing identifier message fails
 * loudly. No third-party protobuf dependency.
 */
object MacHardwareInfoExportCode {

    /** The 4-byte ASCII payload magic (§1.1). */
    const val MAGIC = "OABS"

    /** The hardcoded protocol version the helper puts in outer field 3 (§1.1). */
    const val PROTOCOL_VERSION = 1640L

    private const val RESTRICTED_PREFIX = "Salted__"
    private const val SALT_LENGTH = 8
    private const val DERIVED_LENGTH = 32 + 16

    /** Parses the payload bytes — the QR-code path (§1.1: raw payload bytes, medium EC). */
    fun parsePayload(payload: ByteArray): MacHardwareInfoExport {
        if (payload.size < 5) {
            throw MacHardwareInfoExportException(
                "export payload is ${payload.size} bytes — too short for the $MAGIC magic + flag (§1.1)",
            )
        }
        if (!String(payload, 0, 4, Charsets.US_ASCII).contentEquals(MAGIC)) {
            throw MacHardwareInfoExportException(
                "export payload does not start with the $MAGIC magic (§1.1)",
            )
        }
        val flag = payload[4].toInt() and 0xff
        if (flag > 1) {
            throw MacHardwareInfoExportException("export payload flag byte is $flag — expected 0 or 1 (§1.1)")
        }
        val fields = decodeFields(payload, from = 5)
        var identifierBytes: ByteArray? = null
        var macOsProductVersion: String? = null
        var protocolVersion: Long? = null
        var deviceId: String? = null
        var icloudHelperUserAgent: String? = null
        var aosKitVersion: String? = null
        for (field in fields) {
            when (field.number) {
                1 -> identifierBytes = field.lengthDelimited
                2 -> macOsProductVersion = field.string()
                3 -> protocolVersion = field.varint
                4 -> deviceId = field.string()
                5 -> icloudHelperUserAgent = field.string()
                6 -> aosKitVersion = field.string()
                else -> {} // unknown field — skipped (§1.1: tolerant parse)
            }
        }
        val identifierPayload = identifierBytes
            ?: throw MacHardwareInfoExportException("export payload has no outer field 1 identifier message (§1.1)")
        return MacHardwareInfoExport(
            preventSharing = flag == 1,
            macOsProductVersion = macOsProductVersion,
            protocolVersion = protocolVersion,
            deviceId = deviceId,
            icloudHelperUserAgent = icloudHelperUserAgent,
            aosKitVersion = aosKitVersion,
            identifiers = parseIdentifiers(identifierPayload),
        )
    }

    /**
     * Parses base64 export text — the clipboard path. Plain mode (§1.1: base64 of the payload)
     * needs no [activationCode]; restricted mode (the `Salted__` OpenSSL container) fails
     * without the caller-supplied activation code.
     */
    fun parse(text: String, activationCode: String? = null): MacHardwareInfoExport {
        val decoded = try {
            Base64.getMimeDecoder().decode(text.trim())
        } catch (e: IllegalArgumentException) {
            throw MacHardwareInfoExportException("export text is not decodable base64 (§1.1)", e)
        }
        return if (decoded.size >= 8 && String(decoded, 0, 8, Charsets.US_ASCII) == RESTRICTED_PREFIX) {
            parseRestricted(decoded, activationCode)
        } else {
            parsePayload(decoded)
        }
    }

    /** Restricted mode: decrypt the `Salted__` container with [activationCode], then parse. */
    private fun parseRestricted(container: ByteArray, activationCode: String?): MacHardwareInfoExport {
        val code = activationCode
            ?: throw MacHardwareInfoExportException(
                "export is restricted mode (Salted__ container, §1.1) — the activation code is required",
            )
        if (container.size < RESTRICTED_PREFIX.length + SALT_LENGTH + 16) {
            throw MacHardwareInfoExportException("restricted export container is too short (§1.1)")
        }
        val salt = container.copyOfRange(RESTRICTED_PREFIX.length, RESTRICTED_PREFIX.length + SALT_LENGTH)
        val derived = evpBytesToKey(code.toByteArray(Charsets.UTF_8), salt)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(derived, 0, 32, "AES"),
            IvParameterSpec(derived, 32, 16),
        )
        val payload = try {
            cipher.doFinal(container, RESTRICTED_PREFIX.length + SALT_LENGTH,
                container.size - RESTRICTED_PREFIX.length - SALT_LENGTH)
        } catch (e: Exception) {
            throw MacHardwareInfoExportException(
                "restricted export decryption failed — wrong activation code or corrupt container (§1.1)",
                e,
            )
        }
        return parsePayload(payload)
    }

    /**
     * The legacy OpenSSL EVP_BytesToKey KDF (§1.1): repeated MD5 of previous-hash ‖ password ‖
     * salt, concatenated to [DERIVED_LENGTH] bytes — first 32 = AES-256 key, next 16 = IV.
     */
    private fun evpBytesToKey(password: ByteArray, salt: ByteArray): ByteArray {
        val md5 = MessageDigest.getInstance("MD5")
        val out = ByteArray(DERIVED_LENGTH)
        var prev = ByteArray(0)
        var at = 0
        while (at < DERIVED_LENGTH) {
            md5.reset()
            prev = md5.digest(prev + password + salt)
            val chunk = minOf(prev.size, DERIVED_LENGTH - at)
            System.arraycopy(prev, 0, out, at, chunk)
            at += chunk
        }
        return out
    }

    private fun parseIdentifiers(payload: ByteArray): MacHardwareIdentifiers {
        var productName: String? = null
        var macAddress: ByteArray? = null
        var serial: String? = null
        var platformUuid: String? = null
        var rootDiskUuid: String? = null
        var boardId: String? = null
        var osBuildNumber: String? = null
        var serialEnc: ByteArray? = null
        var platformUuidEnc: ByteArray? = null
        var rootDiskUuidEnc: ByteArray? = null
        var rom: ByteArray? = null
        var romEnc: ByteArray? = null
        var mlb: String? = null
        var mlbEnc: ByteArray? = null
        for (field in decodeFields(payload)) {
            when (field.number) {
                1 -> productName = field.string()
                2 -> macAddress = field.lengthDelimited
                3 -> serial = field.string()
                4 -> platformUuid = field.string()
                5 -> rootDiskUuid = field.string()
                6 -> boardId = field.string()
                7 -> osBuildNumber = field.string()
                8 -> serialEnc = field.lengthDelimited
                9 -> platformUuidEnc = field.lengthDelimited
                10 -> rootDiskUuidEnc = field.lengthDelimited
                11 -> rom = field.lengthDelimited
                12 -> romEnc = field.lengthDelimited
                13 -> mlb = field.string()
                14 -> mlbEnc = field.lengthDelimited
                else -> {} // unknown field — skipped (§1.1: tolerant parse)
            }
        }
        return MacHardwareIdentifiers(
            serialNumber = serial
                ?: throw MacHardwareInfoExportException("export identifier message has no field 3 platform serial (§1.1)"),
            logicBoardSerial = mlb
                ?: throw MacHardwareInfoExportException("export identifier message has no field 13 MLB string (§1.1)"),
            rom = rom
                ?: throw MacHardwareInfoExportException("export identifier message has no field 11 ROM bytes (§1.1)"),
            productName = productName,
            macAddress = macAddress,
            platformUuid = platformUuid,
            rootDiskUuid = rootDiskUuid,
            boardId = boardId,
            osBuildNumber = osBuildNumber,
            serialEnc = serialEnc,
            platformUuidEnc = platformUuidEnc,
            rootDiskUuidEnc = rootDiskUuidEnc,
            romEnc = romEnc,
            mlbEnc = mlbEnc,
        )
    }

    // ---- tolerant protobuf decode (hand-rolled, IdsCsr.kt-style minimalism) ----

    private const val WIRE_VARINT = 0
    private const val WIRE_I64 = 1
    private const val WIRE_LEN = 2
    private const val WIRE_I32 = 5

    private class Field(
        val number: Int,
        val wireType: Int,
        val varint: Long?,
        val lengthDelimited: ByteArray?,
    ) {
        fun string(): String? = lengthDelimited?.toString(Charsets.UTF_8)
    }

    private fun decodeFields(bytes: ByteArray, from: Int = 0): List<Field> {
        val fields = ArrayList<Field>()
        var i = from
        while (i < bytes.size) {
            val tag = readVarint(bytes, i).also { i = it.second }.first
            val number = (tag ushr 3).toInt()
            require(number > 0) { "protobuf field number 0" }
            when (tag.toInt() and 0x7) {
                WIRE_VARINT -> {
                    val value = readVarint(bytes, i).also { i = it.second }.first
                    fields.add(Field(number, WIRE_VARINT, value, null))
                }
                WIRE_I64 -> {
                    fields.add(Field(number, WIRE_I64, null, bytes.copyOfRange(i, i + 8)))
                    i += 8
                }
                WIRE_LEN -> {
                    val length = readVarint(bytes, i).also { i = it.second }.first
                    val lengthInt = length.toInt()
                    require(lengthInt >= 0 && i + lengthInt <= bytes.size) { "protobuf length out of range" }
                    fields.add(Field(number, WIRE_LEN, null, bytes.copyOfRange(i, i + lengthInt)))
                    i += lengthInt
                }
                WIRE_I32 -> {
                    fields.add(Field(number, WIRE_I32, null, bytes.copyOfRange(i, i + 4)))
                    i += 4
                }
                else -> throw MacHardwareInfoExportException(
                    "protobuf wire type ${tag and 0x7} (groups are not expected in the export format, §1.1)",
                )
            }
        }
        return fields
    }

    private fun readVarint(bytes: ByteArray, start: Int): Pair<Long, Int> {
        var value = 0L
        var shift = 0
        var i = start
        while (true) {
            if (i >= bytes.size) throw MacHardwareInfoExportException("protobuf varint runs past the end (§1.1)")
            value = value or ((bytes[i].toLong() and 0x7f) shl shift)
            if (bytes[i].toInt() and 0x80 == 0) return value to i + 1
            shift += 7
            if (shift > 63) throw MacHardwareInfoExportException("protobuf varint longer than 64 bits (§1.1)")
            i++
        }
    }
}
