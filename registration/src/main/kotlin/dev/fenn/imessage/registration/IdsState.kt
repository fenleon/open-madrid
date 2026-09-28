package dev.fenn.imessage.registration

import dev.fenn.imessage.ids.IdsLookupResult

/**
 * **C14 decision** (`TODO(capture)` C14 open): the fixed-tier cache policy —
 * positive results refreshed after 1 day, negative (zero-identity) results
 * after 1 hour, hard expiry after 7 days. Chosen over the server-token-field
 * policy because the real token lifetimes are unmeasured (C10 open, real
 * `session-token-expires/refresh-seconds` values unknown) and this policy
 * needs no unmeasured server constants while still bounding staleness on both
 * sides. The SHA-1 (id cert, APNs token) invalidation key of §2.2 applies in
 * both policies and lives in the store. One object to swap when C14 closes.
 */
object TieredIdentityCachePolicy : IdentityCachePolicy {

    /** §2.2: positive results refresh after 1 day, negative after 1 hour, hard-expire after 7 days. */
    const val POSITIVE_TTL_MS: Long = 24 * 60 * 60 * 1000L
    const val NEGATIVE_TTL_MS: Long = 60 * 60 * 1000L
    const val HARD_TTL_MS: Long = 7L * 24 * 60 * 60 * 1000

    override fun freshness(
        result: IdsLookupResult,
        fetchedAtEpochMs: Long,
        nowEpochMs: Long,
    ): CacheFreshness {
        val ageMs = nowEpochMs - fetchedAtEpochMs
        return when {
            ageMs >= HARD_TTL_MS -> CacheFreshness.STALE
            ageMs >= if (result.identities.isEmpty()) NEGATIVE_TTL_MS else POSITIVE_TTL_MS ->
                CacheFreshness.REFRESH
            else -> CacheFreshness.FRESH
        }
    }
}

// Port note: the originating repo's `object IdsState` (Android Context + Room `IdsStateDatabase`
// singleton + a UI-facing `Status` snapshot whose renewal deadline came from the un-ported
// §6.1 scheduler) is not ported — this module has no Android runtime. The store is the plain
// [IdsStore] seam over an injected [IdsStateDao]; a future Android integration layer
// reconstructs the singleton and the status snapshot on top of it.
