package dev.fenn.imessage.engine

import dev.fenn.imessage.registration.IdsAccountEntity
import dev.fenn.imessage.registration.IdsCachedIdentityEntity
import dev.fenn.imessage.registration.IdsCachedResultEntity
import dev.fenn.imessage.registration.IdsCachedResultWithIdentities
import dev.fenn.imessage.registration.IdsRegisteredUserEntity
import dev.fenn.imessage.registration.IdsStateDao
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.util.Base64
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put

/**
 * JSON-file-backed [IdsStateDao] — the storage seam behind [IdsStore] for the JVM/engine
 * layer (the originating repo's Room implementation is the Android counterpart). One state
 * file under [dir]: every mutation rewrites it atomically (temp file + [move] — a crash
 * before the move leaves the previous state on disk). [dir] is injected — callers hand the
 * app's `filesDir`; tests hand a temp directory. Concurrency: a single mutex serializes
 * read-modify-write; the file is the source of truth for a fresh instance.
 *
 * JSON via kotlinx-serialization's JsonObject builders (no `@Serializable` on the ported
 * entities — they are plain data classes from the clean-room port; byte fields ride base64).
 */
class FileIdsStateDao(
    dir: File,
    /** Injectable for tests: the final publish step (temp file → state file). */
    private val move: (Path, Path) -> Unit = { source, target ->
        runCatching { Files.move(source, target, StandardCopyOption.ATOMIC_MOVE) }
            .getOrElse { Files.move(source, target, StandardCopyOption.REPLACE_EXISTING) }
    },
) : IdsStateDao {

    private val stateFile = File(dir.apply { mkdirs() }, "ids-state.json")
    private val mutex = Mutex()
    private val json = Json { ignoreUnknownKeys = true }
    private var state: StoredState? = null

    private class StoredState {
        var account: IdsAccountEntity? = null
        val users = LinkedHashMap<String, IdsRegisteredUserEntity>()
        val results = LinkedHashMap<String, IdsCachedResultEntity>()
        val identities = LinkedHashMap<String, MutableList<IdsCachedIdentityEntity>>()
    }

    // -- IdsStateDao -----------------------------------------------------------------------

    override suspend fun account(): IdsAccountEntity? = mutex.withLock { load().account }

    override suspend fun upsertAccount(entity: IdsAccountEntity) = mutate { it.account = entity }

    override suspend fun registeredUsers(): List<IdsRegisteredUserEntity> =
        mutex.withLock { load().users.values.toList() }

    override suspend fun registeredUser(userId: String): IdsRegisteredUserEntity? =
        mutex.withLock { load().users[userId] }

    override suspend fun upsertUser(user: IdsRegisteredUserEntity) = mutate { it.users[user.userId] = user }

    override suspend fun removeUser(userId: String) = mutate { it.users.remove(userId) }

    override suspend fun cachedResult(handle: String): IdsCachedResultWithIdentities? = mutex.withLock {
        val state = load()
        state.results[handle]?.let { IdsCachedResultWithIdentities(it, state.identities[handle].orEmpty()) }
    }

    override suspend fun cachedHandles(): List<String> = mutex.withLock { load().results.keys.toList() }

    override suspend fun upsertCachedResult(result: IdsCachedResultEntity) =
        mutate { it.results[result.handle] = result }

    override suspend fun upsertCachedIdentities(identities: List<IdsCachedIdentityEntity>) = mutate { state ->
        identities.forEach { identity ->
            state.identities.getOrPut(identity.handle) { mutableListOf() }.add(identity)
        }
    }

    override suspend fun deleteCachedResult(handle: String) = mutate {
        it.results.remove(handle)
        it.identities.remove(handle)
    }

    override suspend fun deleteCacheExcept(key: String) = mutate { state ->
        state.results.entries.removeIf { it.value.cacheKeySha1 != key }
        state.identities.keys.retainAll(state.results.keys)
    }

    override suspend fun clearCache() = mutate {
        it.results.clear()
        it.identities.clear()
    }

    // -- storage ----------------------------------------------------------------------------

    private fun load(): StoredState {
        state?.let { return it }
        val loaded = StoredState()
        if (stateFile.exists()) {
            val root = json.parseToJsonElement(stateFile.readText()).jsonObject
            root["account"]?.let { if (it !is JsonNull) loaded.account = accountOf(it.jsonObject) }
            root["users"]?.jsonArray?.forEach { user ->
                val entity = userOf(user.jsonObject)
                loaded.users[entity.userId] = entity
            }
            root["cacheResults"]?.jsonArray?.forEach { result ->
                val entity = resultOf(result.jsonObject)
                loaded.results[entity.handle] = entity
            }
            root["cacheIdentities"]?.jsonArray?.forEach { identity ->
                val entity = identityOf(identity.jsonObject)
                loaded.identities.getOrPut(entity.handle) { mutableListOf() }.add(entity)
            }
        }
        state = loaded
        return loaded
    }

    private suspend fun mutate(update: (StoredState) -> Unit) = mutex.withLock {
        val current = load()
        update(current)
        persist(current)
    }

    /** Temp file + [move] — a crash before the move leaves the previous state on disk. */
    private fun persist(state: StoredState) {
        val temp = File(stateFile.parentFile, stateFile.name + ".tmp")
        temp.writeBytes(json.encodeToString(JsonObject.serializer(), encode(state)).toByteArray())
        move(temp.toPath(), stateFile.toPath())
    }

    private fun encode(state: StoredState): JsonObject = buildJsonObject {
        put("account", state.account?.let(::accountJson) ?: JsonNull)
        put("users", JsonArray(state.users.values.map(::userJson)))
        put("cacheResults", JsonArray(state.results.values.map(::resultJson)))
        put("cacheIdentities", JsonArray(state.identities.values.flatten().map(::identityJson)))
    }

    // -- entity JSON mapping ------------------------------------------------------------------

    private fun accountJson(e: IdsAccountEntity): JsonObject = buildJsonObject {
        put("id", e.id)
        put("pushCertDer", e.pushCertDer)
        put("pushCertChainJson", e.pushCertChainJson)
        put("apnsConnectToken", e.apnsConnectToken)
        put("macSerial", e.macSerial)
        put("macBoardId", e.macBoardId)
        put("macUuid", e.macUuid)
        put("macMlb", e.macMlb)
        put("macRom", e.macRom)
        put("macModel", e.macModel)
        put("macBuild", e.macBuild)
        put("delegateAuthToken", e.delegateAuthToken)
        put("delegateProfileId", e.delegateProfileId)
        put("delegateRefreshedAtEpochMs", e.delegateRefreshedAtEpochMs)
        put("lastRegistrationEpochMs", e.lastRegistrationEpochMs)
        put("lastRegisterRawPlist", e.lastRegisterRawPlist)
        put("adiMachineTokensPlist", e.adiMachineTokensPlist)
        put("adiProvisionedAtEpochMs", e.adiProvisionedAtEpochMs)
        put("gsaUsername", e.gsaUsername)
        put("gsaPasswordHash", e.gsaPasswordHash)
        put("gsaAdsId", e.gsaAdsId)
        put("gsaPetToken", e.gsaPetToken)
        put("gsaPetExpiresAtEpochMs", e.gsaPetExpiresAtEpochMs)
    }

    private fun accountOf(o: JsonObject): IdsAccountEntity = IdsAccountEntity(
        id = o.intAt("id") ?: 0,
        pushCertDer = o.bytesAt("pushCertDer"),
        pushCertChainJson = o.stringAt("pushCertChainJson"),
        apnsConnectToken = o.bytesAt("apnsConnectToken"),
        macSerial = o.stringAt("macSerial"),
        macBoardId = o.stringAt("macBoardId"),
        macUuid = o.stringAt("macUuid"),
        macMlb = o.stringAt("macMlb"),
        macRom = o.stringAt("macRom"),
        macModel = o.stringAt("macModel"),
        macBuild = o.stringAt("macBuild"),
        delegateAuthToken = o.stringAt("delegateAuthToken"),
        delegateProfileId = o.stringAt("delegateProfileId"),
        delegateRefreshedAtEpochMs = o.longAt("delegateRefreshedAtEpochMs"),
        lastRegistrationEpochMs = o.longAt("lastRegistrationEpochMs"),
        lastRegisterRawPlist = o.bytesAt("lastRegisterRawPlist"),
        adiMachineTokensPlist = o.bytesAt("adiMachineTokensPlist"),
        adiProvisionedAtEpochMs = o.longAt("adiProvisionedAtEpochMs"),
        gsaUsername = o.stringAt("gsaUsername"),
        gsaPasswordHash = o.bytesAt("gsaPasswordHash"),
        gsaAdsId = o.stringAt("gsaAdsId"),
        gsaPetToken = o.stringAt("gsaPetToken"),
        gsaPetExpiresAtEpochMs = o.longAt("gsaPetExpiresAtEpochMs"),
    )

    private fun userJson(e: IdsRegisteredUserEntity): JsonObject = buildJsonObject {
        put("userId", e.userId)
        put("status", e.status)
        put("identityCertDer", e.identityCertDer)
        put("identityCertNotAfterEpochMs", e.identityCertNotAfterEpochMs)
        put("authCertDer", e.authCertDer)
        put("urisJson", e.urisJson)
        put("nextHbiSeconds", e.nextHbiSeconds)
        put("registeredAtEpochMs", e.registeredAtEpochMs)
    }

    private fun userOf(o: JsonObject): IdsRegisteredUserEntity = IdsRegisteredUserEntity(
        userId = o.stringAt("userId")!!,
        status = o.intAt("status"),
        identityCertDer = o.bytesAt("identityCertDer")!!,
        identityCertNotAfterEpochMs = o.longAt("identityCertNotAfterEpochMs")!!,
        authCertDer = o.bytesAt("authCertDer"),
        urisJson = o.stringAt("urisJson")!!,
        nextHbiSeconds = o.longAt("nextHbiSeconds"),
        registeredAtEpochMs = o.longAt("registeredAtEpochMs")!!,
    )

    private fun resultJson(e: IdsCachedResultEntity): JsonObject = buildJsonObject {
        put("handle", e.handle)
        put("status", e.status)
        put("fetchedAtEpochMs", e.fetchedAtEpochMs)
        put("cacheKeySha1", e.cacheKeySha1)
        put("rawPlist", e.rawPlist)
    }

    private fun resultOf(o: JsonObject): IdsCachedResultEntity = IdsCachedResultEntity(
        handle = o.stringAt("handle")!!,
        status = o.intAt("status")!!,
        fetchedAtEpochMs = o.longAt("fetchedAtEpochMs")!!,
        cacheKeySha1 = o.stringAt("cacheKeySha1")!!,
        rawPlist = o.bytesAt("rawPlist")!!,
    )

    private fun identityJson(e: IdsCachedIdentityEntity): JsonObject = buildJsonObject {
        put("handle", e.handle)
        put("deviceIndex", e.deviceIndex)
        put("expiresSeconds", e.expiresSeconds)
        put("refreshSeconds", e.refreshSeconds)
        put("rawPlist", e.rawPlist)
    }

    private fun identityOf(o: JsonObject): IdsCachedIdentityEntity = IdsCachedIdentityEntity(
        handle = o.stringAt("handle")!!,
        deviceIndex = o.intAt("deviceIndex")!!,
        expiresSeconds = o.longAt("expiresSeconds"),
        refreshSeconds = o.longAt("refreshSeconds"),
        rawPlist = o.bytesAt("rawPlist")!!,
    )

    // -- JSON field helpers (stdlib put(String, String?/Number?) covers the rest) -------------

    private fun JsonObject.stringAt(key: String): String? = primitiveAt(key)?.content
    private fun JsonObject.longAt(key: String): Long? = primitiveAt(key)?.content?.toLong()
    private fun JsonObject.intAt(key: String): Int? = longAt(key)?.toInt()
    private fun JsonObject.bytesAt(key: String): ByteArray? =
        primitiveAt(key)?.content?.let { Base64.getDecoder().decode(it) }

    private fun JsonObject.primitiveAt(key: String): JsonPrimitive? =
        (this[key] as? JsonPrimitive)?.takeIf { it !is JsonNull }

    private fun JsonObjectBuilder.put(key: String, value: ByteArray?) =
        put(key, value?.let { JsonPrimitive(Base64.getEncoder().encodeToString(it)) } ?: JsonNull)
}
