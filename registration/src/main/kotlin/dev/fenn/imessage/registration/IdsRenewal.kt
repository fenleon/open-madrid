package dev.fenn.imessage.registration

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.math.min

/**
 * The §6.1 re-registration deadline across all registered users: the earliest
 * per-user deadline ([nextRenewalAtEpochMs]: min of registration + `next-hbi`
 * and cert `notAfter` − 5 min), capped by the 45-day since-last-registration
 * rule. The cap and the per-cert buffers are client policy constants, not
 * measurements (`TODO(capture)` C41) — layered here, the caller layer, not
 * baked into the store. No users and no last-registration time → null.
 */
fun renewalDeadlineEpochMs(
    users: List<IdsRegisteredUserEntity>,
    lastRegistrationEpochMs: Long?,
): Long? {
    val cap = lastRegistrationEpochMs?.plus(IdsRenewal.CAP_MS)
    val byUsers = users.minOfOrNull {
        nextRenewalAtEpochMs(it.registeredAtEpochMs, it.nextHbiSeconds, it.identityCertNotAfterEpochMs)
    }
    return listOfNotNull(byUsers, cap).minOrNull()
}

/**
 * The §6.1 re-registration scheduler: the timer deadline ([renewalDeadlineEpochMs]),
 * the reactive triggers (private-IDS c=32/c=66, lookup 6005), the 15-second
 * triggered-refresh dedup, and the 5-minute-to-1-day failure backoff. The
 * registration itself is injected ([reRegister]) — it needs live validation
 * data that is `TODO(capture)` C5/C6-blocked (a Mac ≤ 14.3), so nothing here
 * touches the network and the JVM tests drive it end to end.
 *
 * Wiring point: ChatSyncService's periodic tick calls [onTimer] (the 60-second
 * wall-clock recheck of §6.1 is the tick cadence), and the courier push
 * handler calls [onPrivateIdsCommand] / [onLookupError6005] once a courier
 * connection exists (component 2's transport is not wired to a service yet).
 * Command 34 is not a re-register — the caller invalidates the identity cache
 * itself (`IdsStore.clearCache()`).
 */
class IdsRenewal(
    private val nowMs: () -> Long = { System.currentTimeMillis() },
    private val reRegister: suspend (reason: String) -> Result<Unit>,
) {

    /** One trigger decision: [attempted] false = nothing ran (not due, deduped,
     *  rate-limited, not a re-register trigger); a failure carries no error —
     *  the [reRegister] owner logs it. */
    data class Attempt(val attempted: Boolean, val success: Boolean?, val reason: String)

    companion object {
        /**
         * §6.1: force re-registration 45 days after the last successful one —
         * a client policy cap (`TODO(capture)` C41), not a measured Apple TTL.
         */
        const val CAP_MS: Long = 45L * 24 * 60 * 60 * 1000

        /** §6.1: failed registrations retry with exponential backoff, minimum 5 minutes, maximum 1 day. */
        const val BACKOFF_MIN_MS: Long = 5 * 60 * 1000L
        const val BACKOFF_MAX_MS: Long = 24 * 60 * 60 * 1000L

        /** §6.1: a triggered refresh is a no-op within 15 s of the last attempt (any attempt, so a forced trigger cannot hammer a failing registration). */
        const val DEDUP_MS: Long = 15_000L

        /** §6.1: a lookup 6005 triggers re-register and retry at most once per hour. */
        const val RATE_6005_MS: Long = 60 * 60 * 1000L
    }

    private val mutex = Mutex()
    private var failures = 0
    private var backoffUntilMs = 0L
    private var lastAttemptMs = 0L
    private var last6005Ms = 0L

    /** The periodic tick: re-register when the deadline has passed and the failure backoff has run out. */
    suspend fun onTimer(
        users: List<IdsRegisteredUserEntity>,
        lastRegistrationEpochMs: Long?,
    ): Attempt = mutex.withLock {
        val deadline = renewalDeadlineEpochMs(users, lastRegistrationEpochMs)
            ?: return Attempt(false, null, "not registered")
        val now = nowMs()
        if (now < deadline || now < backoffUntilMs) Attempt(false, null, "not due")
        else attempt("timer")
    }

    /**
     * Private-IDS topic push (§2.3/§6.1): c=32 forces re-registration; c=66
     * re-fetches handles and re-registers when they differ from
     * [registeredHandles] (a null [refetchHandles] or an unchanged set does
     * nothing); any other command (including c=34 — cache invalidation, the
     * caller's job) does nothing.
     */
    suspend fun onPrivateIdsCommand(
        command: Int,
        registeredHandles: List<String> = emptyList(),
        refetchHandles: (suspend () -> List<String>?)? = null,
    ): Attempt = mutex.withLock {
        when (command) {
            32 -> attempt("c=32")
            66 -> {
                val fetched = refetchHandles?.invoke()
                if (fetched != null && fetched.toSet() != registeredHandles.toSet()) attempt("c=66")
                else Attempt(false, null, "c=66 handles unchanged")
            }
            else -> Attempt(false, null, "c=$command not a re-register trigger")
        }
    }

    /** Lookup 6005 (§2.3/§6.1): re-register and retry, at most once per hour. */
    suspend fun onLookupError6005(): Attempt = mutex.withLock {
        val now = nowMs()
        if (now - last6005Ms < RATE_6005_MS) Attempt(false, null, "6005 rate-limited")
        else {
            last6005Ms = now
            attempt("6005")
        }
    }

    private suspend fun attempt(reason: String): Attempt {
        val now = nowMs()
        if (lastAttemptMs != 0L && now - lastAttemptMs < DEDUP_MS) {
            return Attempt(false, null, "deduped within 15 s")
        }
        lastAttemptMs = now
        return reRegister(reason).fold(
            onSuccess = {
                failures = 0
                backoffUntilMs = 0L
                Attempt(true, true, reason)
            },
            onFailure = {
                failures++
                backoffUntilMs = now + backoffMs()
                Attempt(true, false, reason)
            },
        )
    }

    /** §6.1: 5 minutes doubling, capped at 1 day. */
    private fun backoffMs(): Long = min(BACKOFF_MAX_MS, BACKOFF_MIN_MS shl (failures - 1).coerceAtMost(12))
}
