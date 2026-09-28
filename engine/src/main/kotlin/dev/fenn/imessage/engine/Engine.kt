package dev.fenn.imessage.engine

import dev.fenn.imessage.courier.CourierClient
import dev.fenn.imessage.courier.CourierCommands
import dev.fenn.imessage.courier.CourierFrame
import dev.fenn.imessage.ids.AppleTrust
import dev.fenn.imessage.ids.CourierTunnelTransport
import dev.fenn.imessage.ids.IdsBagFetcher
import dev.fenn.imessage.ids.IdsHttp
import dev.fenn.imessage.ids.IdsLookupClient
import dev.fenn.imessage.ids.LookupConfig
import dev.fenn.imessage.ids.LookupTransport
import dev.fenn.imessage.registration.IdsKeyPairs
import dev.fenn.imessage.registration.IdsRenewal
import dev.fenn.imessage.registration.IdsStore
import dev.fenn.imessage.registration.TieredIdentityCachePolicy
import java.io.Closeable
import java.io.File
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager

/**
 * The composition root over the ported engine components: HTTP transport, bag fetch, the
 * JSON-file store, the keystore key seam, the renewal scheduler, and the courier connection
 * factory — behind one injected [Config]. Everything is offline-testable: point [Config]
 * .idsBagUrl/[Config].apnsBagUrl at a local mock and hand a temp [Config].workingDir.
 *
 * NOT wired here (app-shell composition, recorded as remaining):
 * - the actual re-registration exchange ([reRegister] is injected — the live path needs the
 *   validation-data generation against real endpoints, C5/C6-blocked);
 * - the foreground-service tick that calls [renewal].onTimer and the courier handler that
 *   feeds tunnel replies / private-IDS pushes into the lookup + renewal pipeline;
 * - the activation flow UI (IdsActivation consumes [keyPairs] + the store directly).
 */
class Engine(
    val config: Config,
    private val reRegister: suspend (reason: String) -> Result<Unit> = {
        Result.failure(IllegalStateException("re-registration is not wired (app-shell composition)"))
    },
) : Closeable {

    class Config(
        /** The engine's state directory — the app shell passes `filesDir` (or a subdir). */
        val workingDir: File,
        /** Endpoint overrides for tests; production keeps the recorded bag URLs. */
        val idsBagUrl: String = IdsBagFetcher.IDS_BAG_URL,
        val apnsBagUrl: String = IdsBagFetcher.APNS_BAG_URL,
        /** Null = platform trust (tests, plain HTTP); production passes AppleTrust's context. */
        val sslContext: SSLContext? = null,
        val connectTimeoutMs: Int = 30_000,
        val requestTimeoutMs: Int = 60_000,
    )

    val http: IdsHttp = JavaNetIdsHttp(
        sslContext = config.sslContext,
        connectTimeoutMs = config.connectTimeoutMs,
        requestTimeoutMs = config.requestTimeoutMs,
    )
    val bagFetcher = IdsBagFetcher(http, config.idsBagUrl, config.apnsBagUrl)
    val store = IdsStore(FileIdsStateDao(config.workingDir), TieredIdentityCachePolicy)
    val keyPairs: IdsKeyPairs = KeystoreIdsKeyPairs()
    val renewal = IdsRenewal(reRegister = reRegister)

    /** The courier connection over [AppleTrust]'s courier anchor (§3.1 [CAP-COURIERTLS]); the
     * Albert client certificate rides as a KeyManager when the app shell supplies one (C18). */
    fun courierConnection(
        courierConfig: CourierClient.Config,
        keyManagers: Array<KeyManager> = emptyArray(),
        trustManagers: Array<TrustManager> = arrayOf(AppleTrust.courierTrustManager()),
    ): CourierConnection = CourierConnection(courierConfig, trustManagers, keyManagers)

    /** A lookup transport over a started courier connection (spec §2.1's tunnel path). */
    fun lookupTransport(fieldIds: CourierCommands.TunnelFieldIds, connection: CourierConnection): LookupTransport =
        CourierTunnelTransport(
            fieldIds,
            sendFrame = { frame ->
                connection.sendFrame(CourierFrame.encode(frame.command, frame.fields.map { it.id to it.value }))
            },
        )

    /** Convenience: the signed lookup client against the fetched bag (spec §2.1, C47 headers). */
    suspend fun lookupClient(transport: LookupTransport, config: LookupConfig): IdsLookupClient =
        IdsLookupClient(transport, bagFetcher.idsBag(), config)

    override fun close() {
        http.close()
    }
}
