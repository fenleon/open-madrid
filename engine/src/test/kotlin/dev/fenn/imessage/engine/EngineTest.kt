package dev.fenn.imessage.engine

import dev.fenn.imessage.codec.XmlPlist
import dev.fenn.imessage.registration.idsRegisteredUser
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * The composition root against a local mock bag server (offline): bag fetch through the
 * engine's HTTP seam, store round-trip through the JSON-file seam, and the renewal host-tick
 * hook. No Apple hosts.
 */
class EngineTest {

    private var server: LocalHttpServer? = null

    @AfterTest
    fun tearDown() {
        server?.stop()
    }

    private fun serveBag(): Int {
        // A recorded-shape IDS bag: outer signature/certs/bag, the embedded `bag` data itself
        // a plist (§1.2 [CAP-BAG]) — built with the :codec writer, served over plain HTTP.
        val inner = XmlPlist.encode(mapOf("id-register" to "https://register.example/wa/register"))
        val outer = XmlPlist.encode(
            mapOf("signature" to ByteArray(8), "certs" to listOf(ByteArray(4)), "bag" to inner),
        )
        LocalHttpServer { _ -> LocalHttpServer.Response(200, body = outer) }.also {
            server = it; it.start()
        }
        return server!!.port
    }

    private fun tempDir() = kotlin.io.path.createTempDirectory("engine").toFile()

    @Test
    fun `bag fetch flows through the engine's http seam`() = runBlocking {
        val url = "http://127.0.0.1:${serveBag()}/bag"
        Engine(Engine.Config(workingDir = tempDir(), idsBagUrl = url, apnsBagUrl = url)).use { engine ->
            assertEquals("https://register.example/wa/register", engine.bagFetcher.idsBag().url("id-register"))
        }
    }

    @Test
    fun `store state persists across engine instances on the same working dir`() = runBlocking {
        val dir = tempDir()
        Engine(Engine.Config(workingDir = dir)).use { engine ->
            assertNull(engine.store.account())
            engine.store.updateAccount { it.copy(macSerial = "ENGINETEST", lastRegistrationEpochMs = 42L) }
        }
        Engine(Engine.Config(workingDir = dir)).use { engine ->
            assertEquals("ENGINETEST", engine.store.account()!!.macSerial)
            assertEquals(42L, engine.store.account()!!.lastRegistrationEpochMs)
        }
    }

    @Test
    fun `renewal tick is wired through the facade with the injected re-register`() = runBlocking {
        val attempts = mutableListOf<String>()
        val engine = Engine(Engine.Config(workingDir = tempDir())) { reason ->
            attempts.add(reason)
            Result.success(Unit)
        }
        // Nothing registered → the tick is a no-op.
        val attempt = engine.renewal.onTimer(emptyList(), null)
        assertEquals(false, attempt.attempted)
        assertEquals("not registered", attempt.reason)
        assertTrue(attempts.isEmpty())
        // With a due registration the host tick drives the injected re-register.
        engine.store.recordRegistration(
            idsRegisteredUser(
                userId = "u",
                status = 0,
                // A real parseable DER — the store reads notAfter at record time.
                identityCertDer = javaClass.getResourceAsStream("/imessage/AppleRootCA-G3.cer")!!.readBytes(),
                uris = listOf("tel:+15551234567"),
                registeredAtEpochMs = 0L,
                nextHbiSeconds = 0, // deadline in the past
            ),
        )
        val due = engine.renewal.onTimer(engine.store.registeredUsers(), 0L)
        assertEquals(true, due.attempted)
        assertEquals(true, due.success)
        assertEquals(listOf("timer"), attempts)
    }
}
