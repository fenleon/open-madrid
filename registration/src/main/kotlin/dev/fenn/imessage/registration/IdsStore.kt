package dev.fenn.imessage.registration

import dev.fenn.imessage.codec.Plist
import dev.fenn.imessage.codec.PlistFormatException
import dev.fenn.imessage.codec.XmlPlist
import dev.fenn.imessage.codec.stringKeyedDictOrNull
import dev.fenn.imessage.codec.typeName
import dev.fenn.imessage.ids.IdsIdentity
import dev.fenn.imessage.ids.IdsLookupResult
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * The persisted iMessage state (spec §1.2/§1.4/§2.1/§2.2/§6.1/§6.2): registration artifacts,
 * session-token lifetimes, and the identity cache send/receive consults.
 *
 * Only what the spec records a client must keep is stored. Unrecorded response fields (C53/C54)
 * ride along as opaque XML-plist blobs — re-encoded with [XmlPlist] so nothing is dropped and
 * nothing is guessed; their typed columns wait for the capture that names the wire keys.
 *
 * Port note: the originating repo backed this with Room (`IdsStateDatabase` + DAO
 * annotations + SQLite migrations). This repo has no Android/Room on the JVM, so the storage
 * contract is the plain [IdsStateDao] interface and the caller supplies the implementation —
 * the registration dry run drives an in-memory DAO (no SQLite, no Android Context); the Room
 * implementation waits for the Android integration.
 */
interface IdsStateDao {
    suspend fun account(): IdsAccountEntity?

    suspend fun upsertAccount(entity: IdsAccountEntity)

    suspend fun registeredUsers(): List<IdsRegisteredUserEntity>

    suspend fun registeredUser(userId: String): IdsRegisteredUserEntity?

    suspend fun upsertUser(user: IdsRegisteredUserEntity)

    suspend fun removeUser(userId: String)

    suspend fun cachedResult(handle: String): IdsCachedResultWithIdentities?

    suspend fun cachedHandles(): List<String>

    suspend fun upsertCachedResult(result: IdsCachedResultEntity)

    suspend fun upsertCachedIdentities(identities: List<IdsCachedIdentityEntity>)

    suspend fun deleteCachedResult(handle: String)

    suspend fun deleteCacheExcept(key: String)

    suspend fun clearCache()
}

/** Singleton row (id always 0) — account-wide artifacts, none keyed per user. */
data class IdsAccountEntity(
    val id: Int = 0,
    /** Albert activation record device certificate, DER (§1.2; the push key itself is Keystore-side). */
    val pushCertDer: ByteArray? = null,
    /** The activation record's certificate chain, JSON array of base64 DERs (§1.2 "plus chain"). */
    val pushCertChainJson: String? = null,
    /** 32-byte APNs connect token from the connect-ack, refreshed whenever a new one arrives (§3.3). */
    val apnsConnectToken: ByteArray? = null,
    // Mac hardware identifiers the renewal's validation-data generation keys off (§6.1 Mac-renewal
    // arbitration). MLB/ROM stay null when the extractor could not derive them (C5/C6).
    val macSerial: String? = null,
    val macBoardId: String? = null,
    val macUuid: String? = null,
    val macMlb: String? = null,
    val macRom: String? = null,
    val macModel: String? = null,
    val macBuild: String? = null,
    /** IDS delegate auth token + profile id from the iCloud setup login (§1.2). */
    val delegateAuthToken: String? = null,
    val delegateProfileId: String? = null,
    /** §6.2: delegate token refreshed lazily when this is older than 7 days (604800 s). */
    val delegateRefreshedAtEpochMs: Long? = null,
    /** Last successful registration — the 45-day forced-renewal cap of §6.1 reads this (C41). */
    val lastRegistrationEpochMs: Long? = null,
    /** The most recent register response's unrecorded fields (per-service breakdown, `alert`,
     *  per-URI statuses, the §6.1 "refresh credentials" marker — wire names C53), XML-plist
     *  encoded. Opaque until the capture names the keys; typed columns then. */
    val lastRegisterRawPlist: ByteArray? = null,
    /** The ADI provisioning machine tokens of §1.1 (start/finish provisioning with gsa.apple.com):
     *  their wire names and value forms are unrecorded (TODO(capture) C6), so the response dict
     *  rides along verbatim, XML-plist encoded — typed columns when the capture names the keys. */
    val adiMachineTokensPlist: ByteArray? = null,
    /** When the machine tokens were provisioned — re-provisioning policy is the caller's. */
    val adiProvisionedAtEpochMs: Long? = null,
    /** GSA login chain (§1.5): the Apple-ID username + the persisted password hash
     *  (SHA-256 of the raw password) the silent PET re-login re-feeds through s2k.
     *  The hash is key material — never logged. */
    val gsaUsername: String? = null,
    val gsaPasswordHash: ByteArray? = null,
    /** The decrypted spd's `adsid` (§1.5) — pairs with the GsIdmsToken in the identity token. */
    val gsaAdsId: String? = null,
    /** The PET (`X-Apple-PE-Token`, §1.5) and its expiry (300 s default, §1.5). */
    val gsaPetToken: String? = null,
    val gsaPetExpiresAtEpochMs: Long? = null,
)

/** One registered user (§1.4 register response, per user). */
data class IdsRegisteredUserEntity(
    val userId: String,
    /** Per-user status from the register response (§1.4's recorded failure codes). */
    val status: Int?,
    /** The X.509 identity certificate (DER) the spec says to store (§1.4). */
    val identityCertDer: ByteArray,
    /** Parsed at store time from [identityCertDer] — the §6.1 fallback renewal bound reads it. */
    val identityCertNotAfterEpochMs: Long,
    /** The longer-lived authentication certificate of §1.2 (signs per-user register requests). */
    val authCertDer: ByteArray? = null,
    /** Registered handle URIs (`tel:`/`mailto:`) — the register body echoes the server's list (§1.4). */
    val urisJson: String,
    /** `next-hbi` of §1.4/§6.1 — seconds from registration until re-registration; null when absent. */
    val nextHbiSeconds: Long? = null,
    val registeredAtEpochMs: Long,
)

/** One handle's cached lookup result (§2.1 response, per handle). Zero-identity rows are kept. */
data class IdsCachedResultEntity(
    val handle: String,
    val status: Int,
    val fetchedAtEpochMs: Long,
    /** [identityCacheKeySha1] of the (id certificate, APNs token) the entry was fetched under (§2.2). */
    val cacheKeySha1: String,
    /** The whole result dict, XML-plist encoded — sender-correlation id and key-transparency
     *  account key included (§2.1; semantics of the former are C11, key names C48). */
    val rawPlist: ByteArray,
)

/** One device identity inside a cached result — the per-device token-timing fields are typed
 *  because both §2.2 cache policies read them; the identity dict itself (client-data, push
 *  token, session token — wire names C48) stays an opaque XML-plist blob. */
data class IdsCachedIdentityEntity(
    val handle: String,
    val deviceIndex: Int,
    val expiresSeconds: Long?,
    val refreshSeconds: Long?,
    val rawPlist: ByteArray,
)

data class IdsCachedResultWithIdentities(
    val result: IdsCachedResultEntity,
    val identities: List<IdsCachedIdentityEntity>,
)

/**
 * Freshness verdict for a cached lookup entry. **Policy is open — TODO(capture) C14**: §2.2
 * records two disagreeing client policies (one reads the server token fields with a SHA-1
 * invalidation key and a 60-second forced-refresh spacing; the other ignores them and uses
 * fixed 1-day/1-hour/7-day tiers), and no default here pretends to be measured. The caller
 * injects one; the 60-second spacing of the first policy is caller-side pacing state, not a
 * store concern.
 */
enum class CacheFreshness { FRESH, REFRESH, STALE }

fun interface IdentityCachePolicy {
    fun freshness(
        result: IdsLookupResult,
        fetchedAtEpochMs: Long,
        nowEpochMs: Long,
    ): CacheFreshness
}

/** A cached lookup entry plus the injected policy's verdict on it. */
data class CachedLookup(
    val fetchedAtEpochMs: Long,
    val result: IdsLookupResult,
    val freshness: CacheFreshness,
)

/**
 * §2.2's cache invalidation key: SHA-1 over the id certificate and the current APNs connect
 * token, so either change invalidates every cached entry. Concatenation is cert-then-token,
 * the order the spec names; hex, lowercase.
 */
fun identityCacheKeySha1(identityCertDer: ByteArray, apnsConnectToken: ByteArray): String =
    MessageDigest.getInstance("SHA-1")
        .digest(identityCertDer + apnsConnectToken)
        .joinToString("") { "%02x".format(it) }

/**
 * §6.1's re-registration schedule (first-source reading, the one with no invented constants):
 * the earliest of (registration time + `next-hbi`) and the identity certificate's `notAfter`
 * minus a 5-minute safety margin; absent `next-hbi` → the certificate bound alone. The second
 * source's tiered buffers and 45-day cap are client policy constants, not measurements (C41) —
 * the caller layers those on top if it wants them, they are not baked in here.
 */
fun nextRenewalAtEpochMs(
    registeredAtEpochMs: Long,
    nextHbiSeconds: Long?,
    identityCertNotAfterEpochMs: Long,
): Long {
    val byCert = identityCertNotAfterEpochMs - 300_000
    val byHbi = nextHbiSeconds?.let { registeredAtEpochMs + it * 1000 } ?: return byCert
    return minOf(byHbi, byCert)
}

/** The X.509 `notAfter` of a DER certificate, epoch ms. */
fun x509NotAfterEpochMs(der: ByteArray): Long =
    (CertificateFactory.getInstance("X.509")
        .generateCertificate(ByteArrayInputStream(der)) as X509Certificate).notAfter.time

/** [IdsRegisteredUserEntity] factory: parses the certificate's `notAfter` at store time. */
fun idsRegisteredUser(
    userId: String,
    status: Int?,
    identityCertDer: ByteArray,
    uris: List<String>,
    registeredAtEpochMs: Long,
    authCertDer: ByteArray? = null,
    nextHbiSeconds: Long? = null,
): IdsRegisteredUserEntity = IdsRegisteredUserEntity(
    userId = userId,
    status = status,
    identityCertDer = identityCertDer,
    identityCertNotAfterEpochMs = x509NotAfterEpochMs(identityCertDer),
    authCertDer = authCertDer,
    urisJson = Json.encodeToString(uris),
    nextHbiSeconds = nextHbiSeconds,
    registeredAtEpochMs = registeredAtEpochMs,
)

fun registeredUserUris(user: IdsRegisteredUserEntity): List<String> =
    Json.decodeFromString(user.urisJson)

/** Activation record chain, JSON array of base64 DERs (see [IdsAccountEntity.pushCertChainJson]). */
fun pushCertChainJson(chainDers: List<ByteArray>): String =
    Json.encodeToString(chainDers.map { java.util.Base64.getEncoder().encodeToString(it) })

fun pushCertChainDers(json: String?): List<ByteArray> =
    json?.let { parsed ->
        Json.decodeFromString<List<String>>(parsed).map { java.util.Base64.getDecoder().decode(it) }
    } ?: emptyList()

/** ADI machine-token dict → opaque plist blob for [IdsAccountEntity.adiMachineTokensPlist]. */
fun adiMachineTokensPlist(raw: Map<String, Any?>): ByteArray = XmlPlist.encode(raw)

/** The stored ADI machine-token dict back out, or null when nothing is provisioned. */
fun adiMachineTokensRaw(plist: ByteArray?): Map<String, Any?>? {
    plist ?: return null
    val parsed = Plist.parse(plist)
    return stringKeyedDictOrNull(parsed)
        ?: throw PlistFormatException("stored ADI machine tokens are ${typeName(parsed)}, expected a dict")
}

internal fun cachedResultEntities(
    handle: String,
    result: IdsLookupResult,
    cacheKeySha1: String,
    fetchedAtEpochMs: Long,
): Pair<IdsCachedResultEntity, List<IdsCachedIdentityEntity>> = IdsCachedResultEntity(
    handle = handle,
    status = result.status,
    fetchedAtEpochMs = fetchedAtEpochMs,
    cacheKeySha1 = cacheKeySha1,
    rawPlist = XmlPlist.encode(result.raw),
) to result.identities.mapIndexed { index, identity ->
    IdsCachedIdentityEntity(
        handle = handle,
        deviceIndex = index,
        expiresSeconds = identity.expiresSeconds,
        refreshSeconds = identity.refreshSeconds,
        rawPlist = XmlPlist.encode(identity.raw),
    )
}

internal fun lookupResultOf(
    result: IdsCachedResultEntity,
    identities: List<IdsCachedIdentityEntity>,
): IdsLookupResult = IdsLookupResult(
    status = result.status,
    identities = identities.sortedBy { it.deviceIndex }.map {
        IdsIdentity(it.expiresSeconds, it.refreshSeconds, decodePlistDict(it.rawPlist))
    },
    raw = decodePlistDict(result.rawPlist),
)

private fun decodePlistDict(bytes: ByteArray): Map<String, Any?> {
    val parsed = Plist.parse(bytes)
    return parsed as? Map<String, Any?>
        ?: throw PlistFormatException("stored raw state is ${parsed?.javaClass?.simpleName}, expected a dict")
}

/**
 * The iMessage state store over [IdsStateDao] (port note above: the Room database of the
 * originating repo is replaced by this plain DAO seam). Component 6 scope: persistence of
 * what the spec records, the injected cache policy (C14), and the recorded renewal schedule.
 * No UI, no renewal scheduling, no network (component 7 owns those).
 */
class IdsStore(
    private val dao: IdsStateDao,
    private val cachePolicy: IdentityCachePolicy,
) {

    suspend fun account(): IdsAccountEntity? = dao.account()

    /** Read-modify-write of the singleton account row (missing row = a fresh default). */
    suspend fun updateAccount(update: (IdsAccountEntity) -> IdsAccountEntity): IdsAccountEntity =
        update(dao.account() ?: IdsAccountEntity()).also { dao.upsertAccount(it) }

    suspend fun recordRegistration(user: IdsRegisteredUserEntity) = dao.upsertUser(user)

    suspend fun registeredUsers(): List<IdsRegisteredUserEntity> = dao.registeredUsers()

    suspend fun registeredUser(userId: String): IdsRegisteredUserEntity? = dao.registeredUser(userId)

    suspend fun removeRegisteredUser(userId: String) = dao.removeUser(userId)

    /**
     * Persists one handle's lookup result under the (id cert, APNs token) cache key of §2.2,
     * replacing any prior entry for the handle. Zero-identity results are stored (negative
     * caching); the identity dicts ride along as opaque XML-plist blobs (wire names C48).
     */
    suspend fun storeLookup(
        handle: String,
        result: IdsLookupResult,
        identityCertDer: ByteArray,
        apnsConnectToken: ByteArray,
        nowEpochMs: Long,
    ) {
        val key = identityCacheKeySha1(identityCertDer, apnsConnectToken)
        val (resultEntity, identityEntities) = cachedResultEntities(handle, result, key, nowEpochMs)
        dao.deleteCachedResult(handle)
        dao.upsertCachedResult(resultEntity)
        dao.upsertCachedIdentities(identityEntities)
    }

    /**
     * §2.2: an id-certificate or APNs-token change invalidates every cached entry — anything
     * not fetched under the current key pair is dropped.
     */
    suspend fun invalidateCache(identityCertDer: ByteArray, apnsConnectToken: ByteArray) {
        dao.deleteCacheExcept(identityCacheKeySha1(identityCertDer, apnsConnectToken))
    }

    /** The cached entry for [handle] (null if none), with the injected policy's verdict. */
    suspend fun cachedLookup(handle: String, nowEpochMs: Long): CachedLookup? {
        val row = dao.cachedResult(handle) ?: return null
        val result = lookupResultOf(row.result, row.identities)
        return CachedLookup(
            fetchedAtEpochMs = row.result.fetchedAtEpochMs,
            result = result,
            freshness = cachePolicy.freshness(result, row.result.fetchedAtEpochMs, nowEpochMs),
        )
    }

    suspend fun cachedHandles(): List<String> = dao.cachedHandles()

    suspend fun clearCache() = dao.clearCache()
}
