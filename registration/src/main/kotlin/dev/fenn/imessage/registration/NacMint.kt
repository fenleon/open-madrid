package dev.fenn.imessage.registration

/**
 * Public facade over the internal NAC mint ([NacValidation], spec §1.1 rev 31 — the 517-B
 * validation stamp, byte-exact vs the live captures): the consumer-visible mint surface for
 * the §1.1 validation-data seam (:engine api-exposes :registration, but internal members
 * stay module-private).
 *
 * Pure math — no transport, no persistence. The mapping from the pinned §1.1 exchange to
 * these inputs is NOT established (§1.1 C56 residue; NAC-NOTES.md closes only the math):
 * callers must not fabricate cert79/session250/rngPad130/body576/pearKey16 — run the
 * exchange and fail loudly at the first unestablished mapping instead.
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
}
