package dev.fenn.imessage.registration

/**
 * Public facade over the internal NAC mint ([NacValidation], spec §1.1 — the 517-B
 * validation stamp): the consumer-visible mint surface for the §1.1 validation-data seam
 * (:engine api-exposes :registration, but internal members stay module-private).
 *
 * Pure math — no transport, no persistence.
 *
 * Input mappings from the live exchange (2026-10-08, three instrumented runs; §1.1):
 * - pearKey16 — 16 fresh client RNG bytes (created in ValidationCtx::new; wrapped to the
 *   server inside the step-2 request blob).
 * - rngPad130 — 130 fresh client RNG bytes (the scramble buffer's thread-RNG filler).
 * - rand16 — 16 fresh client RNG bytes (the mint's own sample).
 * - body576 — keyEstablishment payload[2:578] (the EstablishKeyResponse payload region).
 * - cert79 — keyEstablishmentFull trailing[0:79] (server material from the response —
 *   NOT the step-1 certificate).
 * Still NOT established (§1.1 C56-a/C56-c residue): the step-2 request blob's field
 * construction and the session250 hardware-config serialization — callers must not
 * fabricate them; run the exchange and fail loudly at the first unestablished mapping.
 *
 * KNOWN LIVE DIVERGENCE (§1.1, 2026-10-08): the sig16 pipeline (NacSign) is byte-exact
 * vs the session-20 captures and the python model, but produces a WRONG sig16 for
 * fresh live inputs (all four sign::sign args byte-verified; two independent runs) —
 * do not ship a live mint until §1.1's sign-model residue is closed.
 */
object NacMint {

    /** [NacValidation.mint] — the full 517-B stamp; sig16 computed internally from body576/rand16/blob480. */
    fun mint(
        cert79: ByteArray,
        session250: ByteArray,
        rngPad130: ByteArray,
        rand16: ByteArray,
        body576: ByteArray,
    ): ByteArray = NacValidation.mint(cert79, session250, rngPad130, rand16, body576)

    /** [NacValidation.keyEstablishment] — the SDAT-mapped EstablishKeyResponse wire. */
    fun keyEstablishment(sessionInfo: ByteArray, pearKey16: ByteArray): ByteArray =
        NacValidation.keyEstablishment(sessionInfo, pearKey16)

    /** [NacValidation.keyEstablishmentFull] — payload + the response's trailing Vec. */
    fun keyEstablishmentFull(sessionInfo: ByteArray, pearKey16: ByteArray): Established =
        NacValidation.keyEstablishmentFull(sessionInfo, pearKey16)
}

/** The parsed key-establishment outcome (the ctx fields the mint consumes). */
class Established(
    /** The SDAT-mapped EstablishKeyResponse wire (592 B live). */
    val payload: ByteArray,
    /** The response's trailing Vec (85 B live) — cert79 = [0:0x4f]. */
    val trailing: ByteArray,
)
