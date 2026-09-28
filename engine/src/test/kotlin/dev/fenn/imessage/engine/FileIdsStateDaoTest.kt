package dev.fenn.imessage.engine

import dev.fenn.imessage.registration.IdsAccountEntity
import dev.fenn.imessage.registration.IdsCachedIdentityEntity
import dev.fenn.imessage.registration.IdsCachedResultEntity
import dev.fenn.imessage.registration.idsRegisteredUser
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/** The JSON-file store seam: round-trips, cross-instance persistence, crash-atomicity. */
class FileIdsStateDaoTest {

    private fun tempDir(): File = kotlin.io.path.createTempDirectory("ids-state").toFile()

    private fun user(id: String, registeredAt: Long = 1L) = idsRegisteredUser(
        userId = id,
        status = 0,
        // A real parseable X.509 DER — idsRegisteredUser reads notAfter at store time.
        identityCertDer = javaClass.getResourceAsStream("/imessage/AppleRootCA-G3.cer")!!.readBytes(),
        uris = listOf("tel:+15551234567"),
        registeredAtEpochMs = registeredAt,
        nextHbiSeconds = 800_000,
    )

    @Test
    fun `fresh store is empty`() = runBlocking {
        val dao = FileIdsStateDao(tempDir())
        assertNull(dao.account())
        assertTrue(dao.registeredUsers().isEmpty())
        assertTrue(dao.cachedHandles().isEmpty())
    }

    @Test
    fun `account round-trips every field including bytes`() = runBlocking {
        val dir = tempDir()
        val dao = FileIdsStateDao(dir)
        val account = IdsAccountEntity(
            macSerial = "EMUVERIFY",
            apnsConnectToken = ByteArray(32) { (it * 3).toByte() },
            gsaPasswordHash = ByteArray(32) { 7 },
            lastRegistrationEpochMs = 1_700_000_000_000L,
            gsaPetToken = "pet-token",
        )
        dao.upsertAccount(account)
        val read = dao.account()!!
        assertEquals("EMUVERIFY", read.macSerial)
        assertContentEquals(account.apnsConnectToken, read.apnsConnectToken)
        assertContentEquals(account.gsaPasswordHash, read.gsaPasswordHash)
        assertEquals(1_700_000_000_000L, read.lastRegistrationEpochMs)
        assertEquals("pet-token", read.gsaPetToken)

        // A fresh instance over the same directory reads the persisted state.
        val reopened = FileIdsStateDao(dir)
        assertEquals("EMUVERIFY", reopened.account()!!.macSerial)
        assertContentEquals(account.apnsConnectToken, reopened.account()!!.apnsConnectToken)
    }

    @Test
    fun `registered users upsert remove and persist`() = runBlocking {
        val dir = tempDir()
        val dao = FileIdsStateDao(dir)
        dao.upsertUser(user("b"))
        dao.upsertUser(user("a"))
        assertEquals(listOf("b", "a"), dao.registeredUsers().map { it.userId }) // insertion order
        dao.upsertUser(user("a", registeredAt = 2L))
        assertEquals(2L, dao.registeredUser("a")!!.registeredAtEpochMs)
        dao.removeUser("b")
        assertEquals(listOf("a"), dao.registeredUsers().map { it.userId })

        assertEquals(listOf("a"), FileIdsStateDao(dir).registeredUsers().map { it.userId })
    }

    @Test
    fun `lookup cache round-trips results with their device identities`() = runBlocking {
        val dir = tempDir()
        val dao = FileIdsStateDao(dir)
        dao.upsertCachedResult(
            IdsCachedResultEntity("tel:+15551234567", 200, 42L, "key-1", ByteArray(8) { 1 }),
        )
        dao.upsertCachedIdentities(
            listOf(
                IdsCachedIdentityEntity("tel:+15551234567", 0, 3600, 1800, ByteArray(8) { 2 }),
                IdsCachedIdentityEntity("tel:+15551234567", 1, 7200, 3600, ByteArray(8) { 3 }),
            ),
        )
        val cached = dao.cachedResult("tel:+15551234567")!!
        assertEquals(200, cached.result.status)
        assertEquals("key-1", cached.result.cacheKeySha1)
        assertEquals(2, cached.identities.size)
        assertEquals(7200L, cached.identities[1].expiresSeconds)

        val reopened = FileIdsStateDao(dir)
        assertEquals(2, reopened.cachedResult("tel:+15551234567")!!.identities.size)
    }

    @Test
    fun `delete cache except keeps only the current key pair's entries`() = runBlocking {
        val dao = FileIdsStateDao(tempDir())
        dao.upsertCachedResult(IdsCachedResultEntity("tel:+1", 200, 1L, "current", ByteArray(1)))
        dao.upsertCachedResult(IdsCachedResultEntity("tel:+2", 200, 2L, "stale", ByteArray(1)))
        dao.upsertCachedIdentities(
            listOf(IdsCachedIdentityEntity("tel:+2", 0, 1, 1, ByteArray(1))),
        )
        dao.deleteCacheExcept("current")
        assertEquals(listOf("tel:+1"), dao.cachedHandles())
        assertNull(dao.cachedResult("tel:+2"))
    }

    @Test
    fun `a crash before the atomic move leaves the previous state on disk`() = runBlocking {
        val dir = tempDir()
        val dao = FileIdsStateDao(dir)
        dao.upsertAccount(IdsAccountEntity(macSerial = "v1"))

        // The failing instance simulates a crash between the temp-file write and the move.
        val crashing = FileIdsStateDao(dir) { _, _ -> throw IllegalStateException("crash") }
        assertFailsWith<IllegalStateException> {
            crashing.upsertAccount(IdsAccountEntity(macSerial = "v2"))
        }
        // The temp file was written, the state file untouched: a fresh instance reads v1.
        assertEquals("v1", FileIdsStateDao(dir).account()!!.macSerial)
    }
}
