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
 * - rngPad — the scramble buffer's thread-RNG filler: `0x17c − session250.size` fresh
 *   client RNG bytes (130 on the capture machine, whose session250 is 250 B).
 * - rand16 — 16 fresh client RNG bytes (the mint's own sample).
 * - body576 — keyEstablishment payload[2:578] (the EstablishKeyResponse payload region).
 * - cert79 — keyEstablishmentFull trailing[0:79] (server material from the response —
 *   NOT the step-1 certificate).
 * Established (§1.1 rev 33/35 + C56-c): the request blob ([NacRequestBlob]) and the
 * session250 hardware-config serialization ([HardwareConfiguration.toBin]) — no input
 * mapping remains open.
 */
object NacMint {

    /** [NacValidation.mint] — the full 517-B stamp; sig16 computed internally from body576/rand16/blob480. */
    fun mint(
        cert79: ByteArray,
        session250: ByteArray,
        rngPad: ByteArray,
        rand16: ByteArray,
        body576: ByteArray,
    ): ByteArray = NacValidation.mint(cert79, session250, rngPad, rand16, body576)

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
