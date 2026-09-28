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
import dev.fenn.imessage.crypto.Hkdf
import dev.fenn.imessage.ids.TunnelReply
import dev.fenn.imessage.ids.TunnelStatus
import dev.fenn.imessage.crypto.EcCrypto
import dev.fenn.imessage.crypto.MessageBody
import dev.fenn.imessage.crypto.PairEcEnvelope
import dev.fenn.imessage.crypto.PairEnvelope
import dev.fenn.imessage.crypto.PayloadCommands
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.XECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPublicKeySpec
import javax.crypto.KeyAgreement

/**
 * The hardware configuration the step-3 context consumes (spec §1.1 field set, fully recorded):
 * product name (Apple product-type form), MAC address (exactly 6 raw bytes), platform serial,
 * platform UUID, root-disk UUID, board ID, OS build number, ROM (raw bytes), MLB, plus the five
 * `_enc` obfuscated raw-byte variants under the five recorded fixed labels
 * ([EncLabel]). The `_enc` derivations are closed source (C57) — the values arrive pre-computed
 * in the Mac-Hardware-Info export payload ([MacHardwareInfoExport]) and pass through verbatim;
 * nothing here derives them.
 */
class HardwareConfiguration(
    val productName: String,
    val osBuildNumber: String,
    val platformSerial: String,
    val platformUuid: String,
    val rootDiskUuid: String,
    val boardId: String,
    val macAddress: ByteArray,
    val rom: ByteArray,
    val mlb: String,
    val serialEnc: ByteArray,
    val platformUuidEnc: ByteArray,
    val rootDiskUuidEnc: ByteArray,
    val romEnc: ByteArray,
    val mlbEnc: ByteArray,
) {

    /** The five recorded obfuscation labels mapped to their fields (§1.1 rev-14 extraction). */
    val encVariants: Map<String, ByteArray>
        get() = mapOf(
            EncLabel.SERIAL to serialEnc,
            EncLabel.PLATFORM_UUID to platformUuidEnc,
            EncLabel.ROOT_DISK_UUID to rootDiskUuidEnc,
            EncLabel.ROM to romEnc,
            EncLabel.MLB to mlbEnc,
        )

    /** The recorded §1.1 obfuscation labels, mapped to their fields. */
    object EncLabel {
        const val SERIAL = "Gq3489ugfi"
        const val PLATFORM_UUID = "Fyp98tpgj"
        const val ROOT_DISK_UUID = "kbjfrfpoJU"
        const val ROM = "oycqAZloTNDm"
        const val MLB = "abKPld1EcMni"
    }

    companion object {
        const val MAC_ADDRESS_BYTES = 6

        /** Builds the configuration from a parsed export payload; loud on any §1.1-required absence. */
        fun from(identifiers: MacHardwareIdentifiers): HardwareConfiguration = from(
            productName = identifiers.productName,
            macAddress = identifiers.macAddress,
            platformSerial = identifiers.serialNumber,
            platformUuid = identifiers.platformUuid,
            rootDiskUuid = identifiers.rootDiskUuid,
            boardId = identifiers.boardId,
            osBuildNumber = identifiers.osBuildNumber,
            rom = identifiers.rom,
            mlb = identifiers.logicBoardSerial,
            serialEnc = identifiers.serialEnc,
            platformUuidEnc = identifiers.platformUuidEnc,
            rootDiskUuidEnc = identifiers.rootDiskUuidEnc,
            romEnc = identifiers.romEnc,
            mlbEnc = identifiers.mlbEnc,
        )

        /**
         * Explicit-fields variant: callers outside the export path name every required input.
         * The five `_enc` blobs pass through verbatim (C57: the derivation is closed source).
         */
        fun from(
            productName: String?,
            macAddress: ByteArray?,
            platformSerial: String,
            platformUuid: String?,
            rootDiskUuid: String?,
            boardId: String?,
            osBuildNumber: String?,
            rom: ByteArray,
            mlb: String,
            serialEnc: ByteArray?,
            platformUuidEnc: ByteArray?,
            rootDiskUuidEnc: ByteArray?,
            romEnc: ByteArray?,
            mlbEnc: ByteArray?,
        ): HardwareConfiguration {
            fun optional(value: Any?, name: String): ByteArray {
                if (value == null || (value is ByteArray && value.isEmpty())) {
                    throw ValidationDataException("hardware configuration is missing $name (§1.1)")
                }
                return value as ByteArray
            }
            fun optionalText(value: String?, name: String): String =
                value?.takeIf { it.isNotEmpty() }
                    ?: throw ValidationDataException("hardware configuration is missing $name (§1.1)")

            val mac = optional(macAddress, "the MAC address")
            if (mac.size != MAC_ADDRESS_BYTES) {
                throw ValidationDataException(
                    "hardware MAC address is ${mac.size} bytes — §1.1 requires exactly $MAC_ADDRESS_BYTES",
                )
            }
            return HardwareConfiguration(
                productName = optionalText(productName, "the product name"),
                osBuildNumber = optionalText(osBuildNumber, "the OS build number"),
                platformSerial = platformSerial,
                platformUuid = optionalText(platformUuid, "the platform UUID"),
                rootDiskUuid = optionalText(rootDiskUuid, "the root-disk UUID"),
                boardId = optionalText(boardId, "the board ID"),
                macAddress = mac,
                rom = rom,
                mlb = mlb,
                serialEnc = optional(serialEnc, "the ${EncLabel.SERIAL} (_enc serial) blob"),
                platformUuidEnc = optional(platformUuidEnc, "the ${EncLabel.PLATFORM_UUID} blob"),
                rootDiskUuidEnc = optional(rootDiskUuidEnc, "the ${EncLabel.ROOT_DISK_UUID} blob"),
                romEnc = optional(romEnc, "the ${EncLabel.ROM} blob"),
                mlbEnc = optional(mlbEnc, "the ${EncLabel.MLB} blob"),
            )
        }
    }
}

/**
 * Every non-recorded derivation choice of the step-3 reconstruction, as an explicit named
 * parameter (see [ValidationDataGenerator] — the live server is the arbiter; a capture swaps
 * these without touching the recorded contract).
 */
data class ValidationDataStrategies(
    /** Key-agreement scheme. Default P-256 ECDH — Apple's recorded crypto is NIST-curve-heavy (§4.3). */
    val keyAgreement: KeyAgreementScheme = KeyAgreementScheme.ECDH_P256,
    /** Key-derivation function over the shared secret. */
    val kdf: Kdf = Kdf.HKDF_SHA256,
    /** HKDF `salt` — unrecorded; empty = RFC 5869's zero salt. */
    val kdfSalt: ByteArray = ByteArray(0),
    /** HKDF `info` — unrecorded; empty. */
    val kdfInfo: ByteArray = ByteArray(0),
    /** Final-blob signature algorithm ("signed blob", §1.1 — asymmetric reading is the default). */
    val signature: BlobSignature = BlobSignature.ECDSA_P256_SHA256,
    /** Final/session blob framing. */
    val framing: BlobFraming = BlobFraming.TLV_V1,
    /** How the server `session-info` response is interpreted. */
    val sessionInfo: SessionInfoParsing = SessionInfoParsing.RAW_PUBLIC_POINT,
) {
    /** Key-agreement schemes the reconstruction implements. */
    enum class KeyAgreementScheme { ECDH_P256, X25519 }

    /** KDFs. */
    enum class Kdf { HKDF_SHA256 }

    /** Signature algorithms. HMAC is the symmetric fallback hypothesis. */
    enum class BlobSignature { ECDSA_P256_SHA256, HMAC_SHA256 }

    /** Blob framings. TLV_V1 = the [ValidationDataFraming] tag/2-byte-length/value layout. */
    enum class BlobFraming { TLV_V1 }

    /**
     * Session-info interpretations. RAW_PUBLIC_POINT (default): the whole `session-info` data
     * IS the server's public key-agreement point (33-byte compressed / 65-byte uncompressed
     * SEC1 for P-256; 32 raw u-coordinate bytes for X25519).
     */
    enum class SessionInfoParsing { RAW_PUBLIC_POINT }
}

/** The recorded blob-field tags of the default TLV framing ([ValidationDataFraming]). */
object ValidationDataFields {
    const val PRODUCT_NAME = 0x01
    const val OS_BUILD_NUMBER = 0x02
    const val PLATFORM_SERIAL = 0x03
    const val PLATFORM_UUID = 0x04
    const val ROOT_DISK_UUID = 0x05
    const val BOARD_ID = 0x06
    const val MAC_ADDRESS = 0x07
    const val ROM = 0x08
    const val MLB = 0x09
    const val SERIAL_ENC = 0x0A
    const val PLATFORM_UUID_ENC = 0x0B
    const val ROOT_DISK_UUID_ENC = 0x0C
    const val ROM_ENC = 0x0D
    const val MLB_ENC = 0x0E
    const val CERTIFICATE = 0x0F
    const val KA_PUBLIC_KEY = 0x10
    const val SIGNING_PUBLIC_KEY = 0x11
    const val SIGNATURE = 0x20
}

/**
 * The TLV_V1 framing: per field, one tag byte + a 2-byte big-endian length + the value.
 * [parse] is the recorded "parseable back into the hardware fields" round-trip (§1.1).
 */
object ValidationDataFraming {

    /** One framed field. */
    data class Field(val tag: Int, val value: ByteArray)

    fun frame(fields: List<Field>): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        for (field in fields) {
            out.write(field.tag)
            out.write((field.value.size ushr 8) and 0xff)
            out.write(field.value.size and 0xff)
            out.write(field.value)
        }
        return out.toByteArray()
    }

    fun parse(blob: ByteArray): List<Field> {
        val fields = ArrayList<Field>()
        var i = 0
        while (i < blob.size) {
            if (i + 3 > blob.size) {
                throw ValidationDataException("validation blob framing truncated at offset $i")
            }
            val tag = blob[i].toInt() and 0xff
            val length = ((blob[i + 1].toInt() and 0xff) shl 8) or (blob[i + 2].toInt() and 0xff)
            if (i + 3 + length > blob.size) {
                throw ValidationDataException("validation blob field $tag length $length runs past the end")
            }
            fields.add(Field(tag, blob.copyOfRange(i + 3, i + 3 + length)))
            i += 3 + length
        }
        return fields
    }
}

/**
 * The step-3 validation-data context (spec §1.1 C56): key establishment over the
 * `id-initialize-validation` session info, blob assembly, and the final signature.
 *
 * ponytail: everything below the recorded contract is a HYPOTHESIS. Step 3's math is closed
 * source — upstream ships stubs, so §1.1 records only the API contract, which is the fixed
 * shape of this class: context creation consumes the certificate chain + the hardware
 * configuration and outputs the session-info-request blob ([createSessionInfoRequest]); key
 * establishment consumes the server response ([establishKeys]); signing produces the final blob
 * with no further inputs ([sign]) — all state retained in the context. The live server is the
 * arbiter (C5/C6 remaining); every non-recorded choice is an explicit
 * [ValidationDataStrategies] parameter and the recorded 15-minute validity bound stays
 * server-side (no local enforcement recorded — none applied).
 *
 * No key or blob material is ever passed to a log seam; this class has none.
 */
class ValidationDataGenerator(
    /** The step-1 certificate chain, leaf first (§1.1: the context consumes the chain). */
    certificateChain: List<ByteArray>,
    private val hardware: HardwareConfiguration,
    private val strategies: ValidationDataStrategies = ValidationDataStrategies(),
    private val random: SecureRandom = SecureRandom(),
) {

    init {
        if (certificateChain.isEmpty()) {
            throw ValidationDataException("the validation context needs the step-1 certificate chain (§1.1)")
        }
    }

    private val certificateChain: List<ByteArray> = certificateChain.toList()
    private val kaKeys: KeyPair = generateKaKeys()
    private val signingKeys: KeyPair? =
        if (strategies.signature == ValidationDataStrategies.BlobSignature.ECDSA_P256_SHA256) {
            EcKeys.p256(random)
        } else {
            null
        }
    private var sessionKey: ByteArray? = null

    /**
     * Contract output 1 (§1.1): the session-info-request blob — the best-faith assembly of the
     * hardware configuration, the certificate chain, and this context's fresh key-agreement
     * (and, for the ECDSA strategy, signing) public keys, under the configured framing.
     */
    fun createSessionInfoRequest(): ByteArray = ValidationDataFraming.frame(allFields())

    /**
     * Contract output 2 (§1.1): key establishment over the server's `session-info` response.
     * The shared secret is the configured key agreement against the server point the configured
     * parsing extracts; the session key is the configured KDF over it.
     */
    fun establishKeys(sessionInfo: ByteArray) {
        val shared = when (strategies.keyAgreement) {
            ValidationDataStrategies.KeyAgreementScheme.ECDH_P256 -> agree(
                "ECDH", kaKeys.private, EcKeys.p256Public(sessionInfo),
            )
            ValidationDataStrategies.KeyAgreementScheme.X25519 -> agree(
                "X25519", kaKeys.private, EcKeys.x25519Public(sessionInfo),
            )
        }
        val prk = Hkdf.extract(strategies.kdfSalt, shared)
        sessionKey = Hkdf.expand(prk, strategies.kdfInfo, SESSION_KEY_BYTES)
    }

    /**
     * Contract output 3 (§1.1): the final signed blob — the framed context fields plus the
     * configured signature over them, under [ValidationDataFields.SIGNATURE]. Fails loudly
     * before [establishKeys].
     */
    fun sign(): ByteArray {
        val key = sessionKey
            ?: throw ValidationDataException("establishKeys must run before sign (§1.1 contract order)")
        val body = ValidationDataFraming.frame(allFields())
        val signature = when (strategies.signature) {
            ValidationDataStrategies.BlobSignature.ECDSA_P256_SHA256 -> {
                val signer = Signature.getInstance("SHA256withECDSA")
                signer.initSign(requireNotNull(signingKeys).private)
                signer.update(body)
                signer.sign() // JCE DER encoding — the wire encoding is a reconstruction choice
            }
            ValidationDataStrategies.BlobSignature.HMAC_SHA256 -> Hkdf.hmac(key, body)
        }
        return body + ValidationDataFraming.frame(
            listOf(ValidationDataFraming.Field(ValidationDataFields.SIGNATURE, signature)),
        )
    }

    private fun allFields(): List<ValidationDataFraming.Field> = buildList {
        add(field(ValidationDataFields.PRODUCT_NAME, hardware.productName.toByteArray(Charsets.UTF_8)))
        add(field(ValidationDataFields.OS_BUILD_NUMBER, hardware.osBuildNumber.toByteArray(Charsets.UTF_8)))
        add(field(ValidationDataFields.PLATFORM_SERIAL, hardware.platformSerial.toByteArray(Charsets.UTF_8)))
        add(field(ValidationDataFields.PLATFORM_UUID, hardware.platformUuid.toByteArray(Charsets.UTF_8)))
        add(field(ValidationDataFields.ROOT_DISK_UUID, hardware.rootDiskUuid.toByteArray(Charsets.UTF_8)))
        add(field(ValidationDataFields.BOARD_ID, hardware.boardId.toByteArray(Charsets.UTF_8)))
        add(field(ValidationDataFields.MAC_ADDRESS, hardware.macAddress))
        add(field(ValidationDataFields.ROM, hardware.rom))
        add(field(ValidationDataFields.MLB, hardware.mlb.toByteArray(Charsets.UTF_8)))
        add(field(ValidationDataFields.SERIAL_ENC, hardware.serialEnc))
        add(field(ValidationDataFields.PLATFORM_UUID_ENC, hardware.platformUuidEnc))
        add(field(ValidationDataFields.ROOT_DISK_UUID_ENC, hardware.rootDiskUuidEnc))
        add(field(ValidationDataFields.ROM_ENC, hardware.romEnc))
        add(field(ValidationDataFields.MLB_ENC, hardware.mlbEnc))
        certificateChain.forEach { cert ->
            add(field(ValidationDataFields.CERTIFICATE, cert))
        }
        add(field(ValidationDataFields.KA_PUBLIC_KEY, kaPublicBytes()))
        signingKeys?.let {
            add(field(ValidationDataFields.SIGNING_PUBLIC_KEY, EcCrypto.compress(it.public)))
        }
    }

    private fun field(tag: Int, value: ByteArray) = ValidationDataFraming.Field(tag, value)

    private fun kaPublicBytes(): ByteArray = when (strategies.keyAgreement) {
        ValidationDataStrategies.KeyAgreementScheme.ECDH_P256 -> EcCrypto.compress(kaKeys.public)
        ValidationDataStrategies.KeyAgreementScheme.X25519 -> EcKeys.x25519Raw(kaKeys.public)
    }

    private fun generateKaKeys(): KeyPair = when (strategies.keyAgreement) {
        ValidationDataStrategies.KeyAgreementScheme.ECDH_P256 -> EcKeys.p256(random)
        ValidationDataStrategies.KeyAgreementScheme.X25519 -> EcKeys.x25519(random)
    }

    private fun agree(algorithm: String, privateKey: java.security.PrivateKey, serverPublic: PublicKey): ByteArray {
        val agreement = KeyAgreement.getInstance(algorithm)
        agreement.init(privateKey)
        agreement.doPhase(serverPublic, true)
        return agreement.generateSecret()
    }

    private companion object {
        const val SESSION_KEY_BYTES = 32
    }
}

/** JCE key/point helpers for the reconstruction's schemes (no third-party crypto dependency). */
internal object EcKeys {

    fun p256(random: SecureRandom): KeyPair =
        KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"), random)
        }.generateKeyPair()

    fun x25519(random: SecureRandom): KeyPair =
        KeyPairGenerator.getInstance("X25519").apply {
            initialize(NamedParameterSpec.X25519, random)
        }.generateKeyPair()

    /**
     * A P-256 public point from raw bytes: 33-byte compressed or 65-byte uncompressed SEC1
     * (the [ValidationDataStrategies.SessionInfoParsing.RAW_PUBLIC_POINT] expectation).
     */
    fun p256Public(raw: ByteArray): ECPublicKey = when {
        raw.size == 33 -> EcCrypto.decompress(raw)
        raw.size == 65 && (raw[0].toInt() and 0xff) == 0x04 ->
            EcCrypto.decompress(byteArrayOf(if (raw[64].toInt() and 1 == 1) 0x03 else 0x02) + raw.copyOfRange(1, 33))
        else -> throw ValidationDataException(
            "session-info is not a P-256 public point (${raw.size} bytes) — " +
                "the RAW_PUBLIC_POINT reconstruction does not apply (§1.1 reconstruction)",
        )
    }

    fun x25519Public(raw: ByteArray): PublicKey {
        if (raw.size != 32) {
            throw ValidationDataException(
                "session-info is not a raw X25519 u-coordinate (${raw.size} bytes) — " +
                    "the RAW_PUBLIC_POINT reconstruction does not apply (§1.1 reconstruction)",
            )
        }
        val u = BigInteger(1, raw.reversedArray())
        return KeyFactory.getInstance("X25519").generatePublic(XECPublicKeySpec(NamedParameterSpec.X25519, u))
    }

    /** The 32-byte little-endian u-coordinate of an X25519 public key. */
    fun x25519Raw(key: PublicKey): ByteArray {
        val u = (key as XECPublicKey).u
        val bigEndian = u.toByteArray()
        val out = ByteArray(32)
        val reversed = bigEndian.reversedArray()
        System.arraycopy(reversed, 0, out, 0, minOf(32, reversed.size))
        return out
    }
}
