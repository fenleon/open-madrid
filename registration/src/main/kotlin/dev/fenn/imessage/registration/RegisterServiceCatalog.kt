package dev.fenn.imessage.registration

import java.security.PrivateKey

/**
 * One service entry of the reference client's §1.4 register catalog: the capability record, the
 * sub-service topics, the service's `ec-version`, and the capability keys its `client-data`
 * carries beyond the identity keys ([MadridIdentity.clientData]).
 *
 * The four entries below are the shipped reference's whole register — `api.rs:580 register_ids`
 * sends `[&MADRID_SERVICE, &MULTIPLEX_SERVICE, &FACETIME_SERVICE, &VIDEO_SERVICE]`, and the
 * trapped body (`captures/c56k/ob-trap-20261014-201103/frame-026.bin`, gzip → 13301 B XML
 * plist) carries exactly those four, with the same NGM identity in every one.
 */
class RegisterServiceSpec(
    val service: String,
    val capabilities: List<RegisterCapability>,
    val subServices: List<String>,
    /**
     * The plist type is capture-bound and differs per service: madrid sends the real `1.0`, the
     * other three the integer `1L`.
     */
    val ecVersion: Any,
    /** The capability keys on top of the identity keys — [MadridIdentity.CLIENT_DATA] for madrid. */
    val clientData: Map<String, Any?>,
) {

    fun clientData(identity: MadridIdentity, prekeyBlob: ByteArray): Map<String, Any?> =
        MadridIdentity.clientData(identity, prekeyBlob, ecVersion) + clientData
}

/**
 * The §1.4 register's service catalog — the reference's four services, in its wire order.
 *
 * Facts, and where each is pinned:
 * - the list and its order: `rust/src/api/api.rs:580` (the `id_services` argument) — confirmed
 *   by the captured body's service order;
 * - per-service `capabilities` (flags + name), `sub-services`, and the extra `client-data`
 *   keys: the capture, cross-checked against the vendored constants
 *   (`rustpush/src/imessage/aps_client.rs:17` madrid, `src/findmy.rs:25` multiplex1,
 *   `src/facetime.rs:24/40` facetime.multi + ess).
 *
 * Where the vendored checkout and the shipped binary disagree, the capture wins (the checkout
 * is a later/other build — its multiplex1 lacks `com.apple.private.alloy.findmy.itemsharing-crossaccount`
 * and the three beacon/findmy-plugin capability keys the shipped body carries).
 *
 * The caller decides *which* services to register; the four here are the shape that is known to
 * return status 0 (WORKLOG 2026-10-16 session 35, measured on the reference three times).
 */
object RegisterServiceCatalog {

    val MADRID = RegisterServiceSpec(
        service = RegisterService.MADRID,
        capabilities = listOf(RegisterCapability(flags = 17, name = "Messenger")),
        subServices = listOf(
            "com.apple.private.alloy.sms",
            "com.apple.private.alloy.gelato",
            "com.apple.private.alloy.biz",
            "com.apple.private.alloy.gamecenter.imessage",
        ),
        ecVersion = 1.0,
        clientData = MadridIdentity.CLIENT_DATA,
    )

    val MULTIPLEX1 = RegisterServiceSpec(
        service = "com.apple.private.alloy.multiplex1",
        capabilities = listOf(RegisterCapability(flags = 1, name = "com.apple.private.alloy")),
        subServices = listOf(
            "com.apple.private.alloy.fmf",
            "com.apple.private.alloy.fmd",
            "com.apple.private.alloy.status.keysharing",
            "com.apple.private.alloy.status.personal",
            "com.apple.private.alloy.findmy.itemsharing-crossaccount",
        ),
        ecVersion = 1L,
        clientData = linkedMapOf(
            "supports-fmd-v2" to true,
            "supports-incoming-fmd-v1" to true,
            "supports-findmy-plugin-messages" to true,
            "supports-beacon-sharing-v3" to true,
            "supports-beacon-sharing-v2" to true,
        ),
    )

    val FACETIME_MULTI = RegisterServiceSpec(
        service = "com.apple.private.alloy.facetime.multi",
        capabilities = listOf(RegisterCapability(flags = 1, name = "Invitation")),
        subServices = emptyList(),
        ecVersion = 1L,
        clientData = linkedMapOf(
            "show-peer-errors" to true,
            "supports-avless" to true,
            "supports-co" to true,
            "supports-gft-calls" to true,
            "supports-gft-errors" to true,
            "supports-modern-gft" to true,
            "supports-self-one-to-one-invites" to true,
        ),
    )

    val ESS = RegisterServiceSpec(
        service = "com.apple.ess",
        capabilities = listOf(RegisterCapability(flags = 1, name = "Invitation")),
        subServices = listOf(
            "com.apple.private.alloy.facetime.lp",
            "com.apple.private.alloy.facetime.mw",
            "com.apple.private.alloy.facetime.video",
        ),
        ecVersion = 1L,
        clientData = linkedMapOf(
            "show-peer-errors" to true,
            "supports-gft-errors" to true,
            "supports-live-delivery" to true,
        ),
    )

    /** The reference's register list, in its wire order. */
    val ALL = listOf(MADRID, MULTIPLEX1, FACETIME_MULTI, ESS)

    /**
     * The [ALL] entries as body entries: one service per catalog row, one user each, the same
     * identity in every user (the reference builds `client-data` per service from ONE NGM
     * identity, ONE prekey mint and ONE `kt-loggable-data` blob — both are byte-identical on
     * every service in the capture), and the SAME handle list on every service (it fetches
     * them once per user from `id-get-handles` — [IdsHandleFetcher]).
     */
    fun services(
        identity: MadridIdentity,
        prekeyTimestampEpochSeconds: Long,
        userId: String,
        uris: List<Map<String, String>>,
        authKey: PrivateKey,
        authCertificateDer: ByteArray,
    ): List<RegisterService> {
        val prekeyBlob = identity.prekeyData(prekeyTimestampEpochSeconds)
        val ktLoggableData = identity.ktLoggableData()
        return ALL.map { spec ->
            RegisterService(
                service = spec.service,
                subServices = spec.subServices,
                users = listOf(
                    RegisterUser(
                        userId = userId,
                        uris = uris,
                        tag = null,
                        authKey = authKey,
                        authCertificateDer = authCertificateDer,
                        clientData = spec.clientData(identity, prekeyBlob),
                        ktLoggableData = ktLoggableData,
                    ),
                ),
                capabilities = spec.capabilities,
            )
        }
    }
}
