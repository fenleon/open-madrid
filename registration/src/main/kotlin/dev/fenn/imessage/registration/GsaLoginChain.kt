package dev.fenn.imessage.registration

import dev.fenn.imessage.codec.NativePlist
import dev.fenn.imessage.codec.Plist
import dev.fenn.imessage.codec.PlistDate
import dev.fenn.imessage.codec.PlistFormatException
import dev.fenn.imessage.codec.XmlPlist
import dev.fenn.imessage.codec.integerOrNull
import dev.fenn.imessage.codec.longOrNull
import dev.fenn.imessage.codec.stringKeyedDictOrNull
import dev.fenn.imessage.codec.typeName
import dev.fenn.imessage.courier.CourierClient
import dev.fenn.imessage.courier.CourierCommands
import dev.fenn.imessage.courier.CourierFrame
import dev.fenn.imessage.ids.AppleTrust
import dev.fenn.imessage.ids.Bag
import dev.fenn.imessage.ids.BagKeyMissingException
import dev.fenn.imessage.ids.IdsBagFetcher
import dev.fenn.imessage.ids.IdsHttp
import dev.fenn.imessage.ids.IdsHttpResponse
import dev.fenn.imessage.ids.IdsIdentity
import dev.fenn.imessage.ids.IdsLookupClient
import dev.fenn.imessage.ids.IdsLookupException
import dev.fenn.imessage.ids.IdsLookupResult
import dev.fenn.imessage.ids.IdsSigning
import dev.fenn.imessage.ids.TunnelReply
import dev.fenn.imessage.ids.TunnelStatus
import dev.fenn.imessage.crypto.EcCrypto
import dev.fenn.imessage.crypto.MessageBody
import dev.fenn.imessage.crypto.PairEcEnvelope
import dev.fenn.imessage.crypto.PairEnvelope
import dev.fenn.imessage.crypto.PayloadCommands
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID

/** The §1.5 login outcome: logged-in (with the decrypted `spd` and the PET), or 2FA required. */
sealed interface GsaLoginResult {

    data class Authenticated(
        /** The decrypted §1.5 `spd` (token map, `adsid`, `DsPrsId`, `acname`). */
        val spd: GsaSpd?,
        /** The PET from the response headers (§1.5); null when none was sent. */
        val pet: GsaPet?,
    ) : GsaLoginResult

    /**
     * The complete response's `Status.au` selected secondary auth (§1.5). [identityToken] is
     * the `X-Apple-Identity-Token` built from the decrypted spd when one arrived; null when no
     * spd came back, in which case the caller cannot run 2FA yet (§1.5 derives the token from
     * the spd's `adsid` + `GsIdmsToken`).
     */
    data class SecondaryAuthRequired(
        val variant: String,
        val identityToken: String?,
    ) : GsaLoginResult
}

/**
 * The §1.5 persisted login state: the inputs the silent PET re-login needs (username + the
 * SHA-256 "persisted password hash", §1.5 PET) plus the stored PET and its expiry. The hash
 * is key material — it is persisted but never logged.
 */
data class GsaPersistedCredentials(
    val username: String,
    /** SHA-256 of the raw password — re-fed through the s2k derivation on silent re-login. */
    val passwordHash: ByteArray,
    val adsid: String?,
    val petToken: String?,
    val petExpiresAtEpochMs: Long?,
)

/** The credential-persistence seam behind the orchestrator; [IdsStore] adapter below. */
interface GsaCredentialStore {
    suspend fun load(): GsaPersistedCredentials?
    suspend fun save(credentials: GsaPersistedCredentials)
}

/**
 * The §1.5 adapter: the GSA login state rides the [IdsStore] account row's v3 columns.
 */
class IdsStoreGsaCredentials(private val store: IdsStore) : GsaCredentialStore {

    override suspend fun load(): GsaPersistedCredentials? {
        val account = store.account() ?: return null
        val username = account.gsaUsername ?: return null
        val passwordHash = account.gsaPasswordHash ?: return null
        return GsaPersistedCredentials(
            username = username,
            passwordHash = passwordHash,
            adsid = account.gsaAdsId,
            petToken = account.gsaPetToken,
            petExpiresAtEpochMs = account.gsaPetExpiresAtEpochMs,
        )
    }

    override suspend fun save(credentials: GsaPersistedCredentials) {
        store.updateAccount { account ->
            account.copy(
                gsaUsername = credentials.username,
                gsaPasswordHash = credentials.passwordHash,
                gsaAdsId = credentials.adsid,
                gsaPetToken = credentials.petToken,
                gsaPetExpiresAtEpochMs = credentials.petExpiresAtEpochMs,
            )
        }
    }
}

/**
 * The GSA Apple-ID login chain of spec §1.5, end to end: the SRP-6a login ([GsaSrpClient],
 * [GsaSrpPasswordKey]), M2 verification, `spd` decryption, the two 2FA variants
 * ([GsaTwoFactorClient]) with the recorded "run the SRP login a second time after 2FA"
 * behavior, PET persistence with re-login-on-expiry, and the delegate login
 * ([GsaDelegateLoginClient]) yielding the §1.2 IDS credentials.
 *
 * All transports are injected; no credential material (passwords, hashes,
 * proofs, session keys, tokens) is ever passed to [logEvent].
 */
class GsaLoginChain(
    private val http: IdsHttp,
    private val cpd: GsaCpd,
    private val credentialStore: GsaCredentialStore? = null,
    /** The recorded §1.5 browser-style 2FA header set (C59); null omits it. */
    private val twoFactorBrowserHeaders: GsaTwoFactorHeaders? = null,
    /** The §1.5 akd-variant headers of the GSA POSTs (C59 values) — null omits them. */
    private val headerConfig: GsaHeaderConfig? = null,
    private val random: SecureRandom = SecureRandom(),
    private val clock: () -> Long = System::currentTimeMillis,
    private val logEvent: (String) -> Unit = {},
) {

    private val loginClient = GsaLoginClient(http, logEvent = logEvent)
    private val delegateClient = GsaDelegateLoginClient(http, logEvent = logEvent)

    /** §1.5: the filtered anisette header set + the akd-variant headers, one per login. */
    private fun gsaHeaders(): Map<String, String> =
        headerConfig?.let { cpd.headersFor() + it.toHeaders() } ?: cpd.headersFor()

    /** Full login with the raw password; the hash is computed here and never logged. */
    suspend fun login(username: String, password: String): GsaLoginResult =
        loginWithPasswordHash(username, sha256(password.toByteArray(Charsets.UTF_8)))

    /**
     * Login with the persisted password hash (§1.5 PET: "refreshed by silently re-running the
     * SRP login with the persisted password hash"). Runs init → complete, verifies the server
     * M2, decrypts `spd`, persists the credentials, and returns either
     * [GsaLoginResult.Authenticated] or [GsaLoginResult.SecondaryAuthRequired].
     */
    suspend fun loginWithPasswordHash(username: String, passwordHash: ByteArray): GsaLoginResult {
        val requestUuid = newRequestUuid()
        val cpdDict = cpd.dictFor(requestUuid)
        val gsaHeaders = gsaHeaders()
        val srp = GsaSrpClient(random)
        val a2k = srp.begin()
        val init = loginClient.init(
            GsaInitRequest(username = username, a2k = a2k, cpd = cpdDict, headers = gsaHeaders),
        )
        val passwordKey = GsaSrpPasswordKey.derive(passwordHash, init.salt, init.iterations, init.protocol)
        val proof = srp.proof(
            username = username.toByteArray(Charsets.UTF_8),
            passwordKey = passwordKey,
            salt = init.salt,
            serverPublic = init.serverPublic,
        )
        val complete = loginClient.complete(
            GsaCompleteRequest(
                username = username,
                m1 = proof.m1,
                challenge = init.challenge,
                cpd = cpdDict,
                headers = gsaHeaders,
            ),
            clock(),
        )
        val receivedM2 = complete.m2
            ?: throw GsaLoginException("GSA complete response has no 'M2' data field (§1.5)")
        if (!receivedM2.contentEquals(proof.m2)) {
            throw GsaLoginException("GSA complete: server M2 proof does not match the computed proof (§1.5)")
        }
        val spd = complete.spd?.let { GsaSpd.parse(GsaSpdDecryptor.decrypt(it, proof.k)) }
        return when (val secondaryAuth = complete.secondaryAuth) {
            null -> {
                val result = GsaLoginResult.Authenticated(spd = spd, pet = complete.pet)
                credentialStore?.save(
                    GsaPersistedCredentials(
                        username = username,
                        passwordHash = passwordHash,
                        adsid = spd?.adsid,
                        petToken = complete.pet?.token,
                        petExpiresAtEpochMs = complete.pet?.expiresAtEpochMs,
                    ),
                )
                result
            }
            GsaStatus.AU_SECONDARY_AUTH, GsaStatus.AU_TRUSTED_DEVICE ->
                GsaLoginResult.SecondaryAuthRequired(
                    variant = secondaryAuth,
                    identityToken = spd?.identityToken(),
                )
            else -> throw GsaLoginException(
                "GSA complete 'au' is '$secondaryAuth' — not a recorded secondary-auth variant (§1.5)",
            )
        }
    }

    /** §1.5: `GET .../auth` — the trusted phone numbers (for the SMS 2FA variant). */
    suspend fun trustedPhoneNumbers(identityToken: String): GsaAuthExtras =
        twoFactorClient().trustedPhoneNumbers(identityToken)

    /** Push the code to the trusted devices — must run BEFORE prompting for the code (the
     *  push itself is what makes the code appear; reference: apple-private-apis
     *  `send_2fa_to_devices`). No-op for the SMS variant (its SMS is requested on submit).
     *  Triggering twice before one validate invalidates the outstanding code (observed live). */
    suspend fun triggerTrustedDevicePush(variant: String, identityToken: String) {
        if (variant == GsaStatus.AU_TRUSTED_DEVICE) {
            twoFactorClient().triggerTrustedDevice(identityToken)
        }
    }

    /**
     * §1.5: resolve secondary auth with [securityCode], then — the recorded behavior — run the
     * full SRP login a SECOND time, which then completes as logged-in.
     *
     * [identityToken] is the `X-Apple-Identity-Token` from [GsaLoginResult.SecondaryAuthRequired];
     * [phoneNumberId] is required for the `secondaryAuth` (SMS) variant.
     */
    suspend fun completeSecondaryAuth(
        username: String,
        passwordHash: ByteArray,
        variant: String,
        identityToken: String,
        securityCode: String,
        phoneNumberId: String? = null,
    ): GsaLoginResult {
        val twoFactor = twoFactorClient()
        when (variant) {
            GsaStatus.AU_SECONDARY_AUTH -> {
                val phoneId = requireNotNull(phoneNumberId) {
                    "the SMS 2FA variant needs a trusted-phone id (§1.5 AuthenticationExtras)"
                }
                twoFactor.requestSmsCode(identityToken, phoneId)
                twoFactor.submitSmsCode(identityToken, phoneId, securityCode, clock())
            }
            GsaStatus.AU_TRUSTED_DEVICE -> {
                // The push already fired when the login surfaced the 2FA prompt
                // (triggerTrustedDevicePush) — triggering again would invalidate
                // the first code and re-prompt the devices (observed live).
                twoFactor.submitTrustedDeviceCode(identityToken, securityCode, clock())
            }
            else -> throw GsaLoginException(
                "unknown secondary-auth variant '$variant' (§1.5 records $GSA_STATUS_SECONDARY and $GSA_STATUS_TRUSTED)",
            )
        }
        logEvent("gsa 2fa: accepted — re-running the SRP login (§1.5)")
        return loginWithPasswordHash(username, passwordHash)
    }

    /**
     * The stored PET when it has not expired; otherwise the recorded silent re-login with the
     * persisted password hash (§1.5). Null when nothing usable is persisted or no store is
     * wired. The §1.5 PET default expiry (300 s, no trailer) is applied at parse time.
     */
    suspend fun petToken(nowEpochMs: Long = clock()): String? {
        val store = credentialStore ?: return null
        val saved = store.load() ?: return null
        saved.petToken?.let { token ->
            saved.petExpiresAtEpochMs?.let { expiry -> if (expiry > nowEpochMs) return token }
        }
        if (saved.passwordHash.isEmpty()) return null
        val result = loginWithPasswordHash(saved.username, saved.passwordHash)
        return (result as? GsaLoginResult.Authenticated)?.pet?.token
    }

    /**
     * The §1.5 delegate login: POST `setup.icloud.com/setup/signin/v2/login` with Basic
     * `username:PET`; returns the IDS delegate's `authToken`/`profileId`. [validationData] is
     * the §1.1 blob (the chunk-C exchange mints it — caller-supplied here). [timezone] defaults
     * to the recorded value (§1.5 C59); [clientInfo] defaults to the recorded bracketed AOSKit
     * form when the device config is wired ([GsaHeaderConfig.signInClientInfo]), falling back to
     * the bare recorded AOSKit inner component. [anisette] must be FRESHLY minted for this
     * call — the one-time OTP headers spent on the GSA hops are refused here (observed live;
     * the reference client mints per request).
     */
    suspend fun idsDelegateCredentials(
        username: String,
        pet: String,
        adsid: String,
        validationData: ByteArray,
        timezone: String = GsaDelegateLoginClient.SIGNIN_TIMEZONE,
        clientInfo: String = headerConfig?.signInClientInfo ?: GsaDelegateLoginClient.AOSKIT_CLIENT_INFO,
        anisette: Map<String, String>,
        clientId: String = newRequestUuid(),
    ): IdsDelegateCredentials = delegateClient.signIn(
        IcloudSignInRequest(
            username = username,
            pet = pet,
            adsid = adsid,
            validationData = validationData,
            clientId = clientId,
            timezone = timezone,
            clientInfo = clientInfo,
            anisette = anisette,
        ),
    ).idsDelegateCredentials()

    /**
     * The natural next step of the chain: hand the delegate credentials to the existing §1.2
     * authenticate path — `authentication-data` = {`auth-token`: …}, realm user id =
     * `profile-id`.
     */
    suspend fun authenticateIds(
        credentials: IdsDelegateCredentials,
        bagKey: String,
        csrDer: ByteArray,
        authenticator: IdsAuthenticator,
    ): IdsAuthenticateResponse = authenticator.authenticate(
        bagKey = bagKey,
        realmUserId = credentials.profileId,
        csrDer = csrDer,
        authenticationData = AuthenticationData.AuthToken(credentials.authToken),
    )

    private fun twoFactorClient() = GsaTwoFactorClient(
        http = http,
        browserHeaders = twoFactorBrowserHeaders,
        logEvent = logEvent,
    )

    private fun GsaSpd.identityToken(): String = gsaIdentityToken(
        adsid = adsid
            ?: throw GsaLoginException("spd has no 'adsid' — cannot build the X-Apple-Identity-Token (§1.5)"),
        idmsToken = gsIdmsToken
            ?: throw GsaLoginException(
                "spd has no top-level 'GsIdmsToken' string — cannot build the X-Apple-Identity-Token (§1.5)",
            ),
    )

    private fun newRequestUuid(): String = UUID.randomUUID().toString().uppercase()

    private fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    companion object {
        const val GSA_STATUS_SECONDARY = GsaStatus.AU_SECONDARY_AUTH
        const val GSA_STATUS_TRUSTED = GsaStatus.AU_TRUSTED_DEVICE
    }
}
