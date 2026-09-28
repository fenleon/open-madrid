package dev.fenn.imessage.registration

import dev.fenn.imessage.ids.IdsIdentity
import dev.fenn.imessage.ids.IdsLookupResult
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * [IdsRenewal] end to end on the JVM — the registration itself is injected, so
 * the scheduler's full trigger/backoff logic runs without a device. Entities
 * are plain data classes, constructed directly. [TieredIdentityCachePolicy]'s
 * verdict boundaries are covered too (it is pure).
 */
class IdsRenewalTest {

    private class Harness(var now: Long = 1_000_000_000_000L) {
        val attempts = mutableListOf<String>()
        var fail = false
        val renewal = IdsRenewal(nowMs = { now }) { reason ->
            attempts.add(reason)
            if (fail) Result.failure(IllegalStateException("registration failed"))
            else Result.success(Unit)
        }
    }

    private fun user(registeredAt: Long, hbi: Long?, notAfter: Long) = IdsRegisteredUserEntity(
        userId = "u",
        status = 0,
        identityCertDer = byteArrayOf(1),
        identityCertNotAfterEpochMs = notAfter,
        urisJson = "[\"tel:+15551234567\"]",
        nextHbiSeconds = hbi,
        registeredAtEpochMs = registeredAt,
    )

    @Test
    fun `deadline is the earliest per-user bound capped at 45 days since last registration`() {
        val registeredAt = 1_000_000_000_000L
        val farFuture = registeredAt + 100L * 24 * 60 * 60 * 1000 // beyond the cap
        val a = user(registeredAt, hbi = 90L * 24 * 60 * 60, notAfter = farFuture)
        val b = user(registeredAt, hbi = 80L * 24 * 60 * 60, notAfter = farFuture)
        // Earliest hbi bound wins across users.
        assertEquals(registeredAt + 80L * 24 * 60 * 60 * 1000, renewalDeadlineEpochMs(listOf(a, b), null))
        // 45-day cap applies (C41 client policy, caller-layered).
        assertEquals(
            registeredAt + IdsRenewal.CAP_MS,
            renewalDeadlineEpochMs(listOf(a), registeredAt),
        )
        // Nothing registered → null.
        assertEquals(null, renewalDeadlineEpochMs(emptyList(), null))
    }

    @Test
    fun `timer fires only past the deadline and respects failure backoff`() = Harness().let { h -> runBlocking {
        val registeredAt = h.now
        val users = listOf(user(registeredAt, hbi = 60_000, notAfter = registeredAt + 100L * 24 * 60 * 60 * 1000))
        // Not due.
        assertEquals(false, h.renewal.onTimer(users, registeredAt).attempted)
        h.now += 59_999 * 1000
        assertEquals(false, h.renewal.onTimer(users, registeredAt).attempted)
        // Due → attempt, success clears state.
        h.now += 1_000
        val due = h.renewal.onTimer(users, registeredAt)
        assertTrue(due.attempted && due.success == true)
        // A re-registered schedule (registration time moves to now) is not due again.
        h.now += 60_000 * 1000
        assertEquals(
            false,
            h.renewal.onTimer(listOf(user(h.now, hbi = 60_000, notAfter = h.now + 100L * 24 * 60 * 60 * 1000)), h.now).attempted,
        )
    } }

    @Test
    fun `timer backs off exponentially after failures, capped at 1 day`() = Harness().let { h -> runBlocking {
        h.fail = true
        val registeredAt = h.now
        val users = listOf(user(registeredAt, hbi = 0, notAfter = registeredAt + 100L * 24 * 60 * 60 * 1000))
        assertTrue(h.renewal.onTimer(users, registeredAt).attempted)
        // Backoff: still inside each window → not attempted.
        repeat(6) {
            h.now += 1
            assertEquals(false, h.renewal.onTimer(users, registeredAt).attempted, "retry $it must back off")
        }
        // Jump past the first backoff window → retry fires; failure count increments.
        h.now = registeredAt + IdsRenewal.BACKOFF_MIN_MS + 1
        assertTrue(h.renewal.onTimer(users, h.now).attempted)
        h.now = h.now + 2 * IdsRenewal.BACKOFF_MIN_MS + 1
        assertTrue(h.renewal.onTimer(users, h.now).attempted)
        // Success resets everything (clock past every backoff + dedup window).
        h.fail = false
        h.now += IdsRenewal.BACKOFF_MAX_MS
        assertTrue(h.renewal.onTimer(listOf(user(h.now, 0, h.now + 1)), h.now).attempted)
        assertTrue(h.attempts.last() == "timer")
    } }

    @Test
    fun `c32 forces re-registration and c66 re-registers only on a handle change`() = Harness().let { h -> runBlocking {
        val registered = listOf("tel:+15551234567")
        // c=32 → attempt.
        assertTrue(h.renewal.onPrivateIdsCommand(32).attempted)
        h.now += IdsRenewal.DEDUP_MS // past the 15-second dedup window
        // c=66 unchanged → no attempt.
        assertFalse(h.renewal.onPrivateIdsCommand(66, registered) { registered }.attempted)
        // c=66 with no fetcher → no attempt.
        assertFalse(h.renewal.onPrivateIdsCommand(66, registered).attempted)
        // c=66 changed → attempt.
        assertTrue(h.renewal.onPrivateIdsCommand(66, registered) { listOf("tel:+15550000000") }.attempted)
        // c=34 and unknown commands are not re-register triggers (c=34 → the caller clears the cache).
        assertFalse(h.renewal.onPrivateIdsCommand(34).attempted)
        assertFalse(h.renewal.onPrivateIdsCommand(130).attempted)
        assertEquals(listOf("c=32", "c=66"), h.attempts)
    } }

    @Test
    fun `c66 compares handle sets ignoring order`() = Harness().let { h -> runBlocking {
        val registered = listOf("tel:+15551234567", "mailto:a@example.com")
        assertFalse(h.renewal.onPrivateIdsCommand(66, registered) { listOf("mailto:a@example.com", "tel:+15551234567") }.attempted)
        assertFalse(h.attempts.contains("c=66"))
    } }

    @Test
    fun `6005 is rate-limited to once per hour`() = Harness().let { h -> runBlocking {
        assertTrue(h.renewal.onLookupError6005().attempted)
        h.now += IdsRenewal.RATE_6005_MS - 1
        assertFalse(h.renewal.onLookupError6005().attempted)
        h.now += 1
        assertTrue(h.renewal.onLookupError6005().attempted)
        assertEquals(listOf("6005", "6005"), h.attempts)
    } }

    @Test
    fun `a trigger within 15 seconds of the last attempt is a no-op`() = Harness().let { h -> runBlocking {
        assertTrue(h.renewal.onPrivateIdsCommand(32).attempted)
        h.now += IdsRenewal.DEDUP_MS - 1
        val deduped = h.renewal.onPrivateIdsCommand(32)
        assertFalse(deduped.attempted)
        assertEquals("deduped within 15 s", deduped.reason)
        h.now += 1
        assertTrue(h.renewal.onPrivateIdsCommand(32).attempted)
    } }

    @Test
    fun `tiered cache policy verdicts`() {
        val now = 1_000_000_000_000L
        val positive = IdsLookupResult(
            status = 200,
            identities = listOf(IdsIdentity(3600, 60, emptyMap())),
            raw = emptyMap(),
        )
        val negative = IdsLookupResult(status = 404, identities = emptyList(), raw = emptyMap())
        // Fresh inside the tier; REFRESH past it; STALE past the hard bound.
        assertEquals(CacheFreshness.FRESH, TieredIdentityCachePolicy.freshness(positive, now - 1, now))
        assertEquals(CacheFreshness.REFRESH, TieredIdentityCachePolicy.freshness(positive, now - TieredIdentityCachePolicy.POSITIVE_TTL_MS, now))
        // A negative result is past its 1-hour tier long before the positive tier.
        assertEquals(CacheFreshness.REFRESH, TieredIdentityCachePolicy.freshness(negative, now - TieredIdentityCachePolicy.POSITIVE_TTL_MS, now))
        assertEquals(CacheFreshness.REFRESH, TieredIdentityCachePolicy.freshness(negative, now - TieredIdentityCachePolicy.NEGATIVE_TTL_MS, now))
        assertEquals(CacheFreshness.STALE, TieredIdentityCachePolicy.freshness(positive, now - TieredIdentityCachePolicy.HARD_TTL_MS, now))
    }
}
