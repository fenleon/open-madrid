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
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * The END-TO-END activation dry run (spec §1.1–§1.5): the COMPLETE journey in one flow against
 * one scripted fake-Apple environment ([DryRunAppleEnvironment]) —
 *
 * 1. parse a Mac-Hardware-Info export payload (all recorded fields incl. the five `_enc`
 *    blobs, §1.1 C58) → hardware identifiers;
 * 2. ADI provisioning (start/finish → machine tokens) → the real [AnisetteHeaderProvider]
 *    header set (OTP via the injected test seam);
 * 3. the three-step validation-data exchange (bag cert fetch, body-only session-info POST,
 *    step-3 reconstruction blob) — the blob is asserted verbatim in BOTH sinks later
 *    (`validation-data` in the register body, base64 in `X-Mme-Nas-Qualify`);
 * 4. albert activation (FairPlay signature verified server-side against the wire
 *    FairPlayCertChain; device certificate issued);
 * 5. GSA login (M1 verified server-side, spd decrypted, trusted-device 2FA with the recorded
 *    "second login round", PET persisted) → delegate sign-in (Basic username:PET,
 *    X-Mme-Nas-Qualify = the step-3 blob) → IDS auth-token/profile-id;
 * 6. authenticate (gzipped CSR exchange, CN = hex SHA-1 of the realm user id) → identity
 *    certificate → register (the eight recorded keys, users inside service entries, push +
 *    per-user signature sets) → per-URI statuses;
 * 7. the store ends with the exact end state the session gate needs: provisioned ADI state,
 *    PET + delegate tokens, device/identity/auth certificates, a registered user row with
 *    URI statuses.
 *
 * Every hop is spec-pinned (the fake servers fail loudly), so the ONLY untested hop in a live
 * attempt is the real network.
 *
 * **Structural spots** (spec-unrecorded, asserted only as wiring, never as wire facts):
 * - ADI provisioning paths, body keys, and response field names, and the machine-identifier
 *   wire form (§1.1, TODO(capture) C6) — the exchange composes, nothing more is claimed.
 * - The OTP derivation (C6) — the test seam answers; the provider's value forms are the
 *   recorded ones (`X-Apple-I-Client-Time` = whole-seconds RFC 3339 `Z`, §1.1).
 * - Step-3 blob content (§7 item 24 / C60): only the framing (TLV parse, SIGNATURE last) is
 *   asserted — the reconstruction's six hypotheses are live-arbitrated, not fakeable here.
 * - The APNs connect token in the register config comes from the courier connect-ack (§3.3),
 *   out of this journey's scope — a fixture token rides structurally.
 * - Register `uris` are the server's echoed handle list (§1.4) — the environment's registered
 *   handle is echoed; the id-get-handles fetch is not part of this journey.
 * - The issued certificates are real parseable X.509 stand-ins (staged Apple intermediates):
 *   a fake server issues no real certs, and the store requires parseable DER (`notAfter`).
 */
class ActivationDryRunTest {

    private val username = "user@example.com"
    private val password = "correct horse battery staple"
    private val passwordHash = MessageDigest.getInstance("SHA-256").digest(password.toByteArray(Charsets.UTF_8))

    @Test
    fun `the complete activation journey composes end to end against the scripted apple environment`() = runBlocking {
        val now = 1_770_000_000_000L
        val env = DryRunAppleEnvironment(passwordHash)

        // ------------------------------------------------------------------
        // 1. Parse the Mac-Hardware-Info export payload (§1.1 C58).
        // ------------------------------------------------------------------
        val export = MacHardwareInfoExportCode.parsePayload(exportPayload(flag = 0))
        val identifiers = export.identifiers
        assertEquals(1640L, export.protocolVersion)
        assertEquals("MacBookPro18,3", identifiers.productName)
        assertEquals("C02DRYRUNMAC", identifiers.serialNumber)
        assertEquals("MLB-DRYRUN-STRING", identifiers.logicBoardSerial)
        assertEquals(6, identifiers.macAddress!!.size)
        // The five `_enc` blobs ride the export verbatim (C57: the derivation is closed source).
        assertContentEquals(byteArrayOf(1, 2, 3), identifiers.serialEnc)
        assertContentEquals(byteArrayOf(4, 5), identifiers.platformUuidEnc)
        assertContentEquals(byteArrayOf(6), identifiers.rootDiskUuidEnc)
        assertContentEquals(ROM, identifiers.rom)
        assertContentEquals(byteArrayOf(7, 8, 9, 10), identifiers.romEnc)
        assertContentEquals(byteArrayOf(11, 12), identifiers.mlbEnc)

        // ------------------------------------------------------------------
        // 2. ADI provisioning → machine tokens → the real anisette header set.
        // ------------------------------------------------------------------
        val provisioner = AdiProvisioner(env)
        val start = provisioner.start(
            AdiProvisioningRequest(adiUrl("start"), emptyMap(), XmlPlist.encode(mapOf("phase" to "start")), PROVISIONING_CONTENT_TYPE),
        )
        val finish = provisioner.finish(
            AdiProvisioningRequest(adiUrl("finish"), emptyMap(), XmlPlist.encode(mapOf("phase" to "finish")), PROVISIONING_CONTENT_TYPE),
        )
        assertEquals(1, env.adiStartCount)
        assertEquals(1, env.adiFinishCount)
        // The recorded host fact (§1.1): gsa.apple.com. Paths/body keys are structural (C6).
        assertTrue(env.callUrls().containsAll(listOf(env.adiStartUrl, env.adiFinishUrl)))
        val machineTokens = requireNotNull(finish.plist) { "ADI finish response is not a plist (structural, C6)" }
        val machineIdentifier = machineTokens["machine-identifier"] as ByteArray
        assertContentEquals(env.machineIdentifier, machineIdentifier)

        val otpSeam = AnisetteOtpTestDouble("dry-run-otp".toByteArray())
        val anisetteFormats = AnisetteValueFormats(
            // The recorded §1.1 form: UTC now truncated to whole seconds, RFC 3339 with `Z`.
            clientTime = { ms -> java.time.Instant.ofEpochMilli(ms).truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString() },
            timeZone = "UTC",
            locale = "en_US",
            rinfo = "17106176", // capture-bound value (C6) — caller-supplied
            deviceId = "6a7d4e10-9c2b-4f11-8a33-0d5e1f2a3b4c", // §1.1 recorded form: lowercase hyphenated UUID (caller-supplied value)
        )
        val anisetteProvider = AnisetteHeaderProvider(machineIdentifier, identifiers, otpSeam, anisetteFormats)
        val anisette = anisetteProvider.headers(now, oneTimeIdentifier = ByteArray(8) { (it + 1).toByte() })
        // The recorded §1.1 header set: the seven base headers + the three macOS hardware headers.
        assertEquals(
            listOf(
                "X-Apple-I-Client-Time", "X-Apple-I-TimeZone", "X-Apple-Locale", "X-Apple-I-MD-RINFO",
                "X-Mme-Device-Id", "X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MLB", "X-Apple-I-ROM",
                "X-Apple-I-SRL-NO",
            ),
            anisette.keys.toList(),
        )
        assertTrue(Regex("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$").matches(anisette["X-Apple-I-Client-Time"]!!))
        assertEquals(Base64.getEncoder().encodeToString("dry-run-otp".toByteArray()), anisette["X-Apple-I-MD"])
        assertEquals(Base64.getEncoder().encodeToString(machineIdentifier), anisette["X-Apple-I-MD-M"])
        assertEquals("MLB-DRYRUN-STRING", anisette["X-Apple-I-MLB"])
        assertEquals(ROM.joinToString("") { "%02x".format(it) }, anisette["X-Apple-I-ROM"])
        assertEquals("C02DRYRUNMAC", anisette["X-Apple-I-SRL-NO"])
        // The OTP seam consumed the machine state from the provisioning response.
        assertContentEquals(machineIdentifier, otpSeam.inputs.single().machineIdentifier)

        // ------------------------------------------------------------------
        // 3. The validation-data exchange (§1.1 steps 1–2 wire shapes + step 3 blob).
        // ------------------------------------------------------------------
        val bagFetcher = IdsBagFetcher(env) // process-lifetime cache (§1.2) — ONE bag fetch in the journey
        val validation = ValidationDataExchange(
            http = env,
            bags = bagFetcher,
            logEvent = {},
        ).generate(identifiers, nowEpochMs = now)

        // Step order and bag-resolved URLs (endpoints never hardcoded, §1.2).
        assertEquals(
            listOf(IdsBagFetcher.IDS_BAG_URL, env.certUrl, env.initUrl),
            env.callUrls().takeLast(3),
        )
        assertEquals(1, env.bagFetches)
        assertEquals(1, env.validationCertFetches)
        assertEquals(1, env.initializeCount)
        // The blob is well-framed signed output of the step-3 reconstruction (C60 default).
        assertEquals(
            ValidationDataFields.SIGNATURE,
            ValidationDataFraming.parse(validation.blob).last().tag,
        )

        val store = IdsStore(InMemoryIdsStateDao(), IdentityCachePolicy { _, _, _ -> CacheFreshness.FRESH })
        store.updateAccount { account ->
            account.copy(
                adiMachineTokensPlist = adiMachineTokensPlist(machineTokens),
                adiProvisionedAtEpochMs = now,
            )
        }

        // ------------------------------------------------------------------
        // 4. Albert activation (§1.2) — device certificate for the push key.
        // ------------------------------------------------------------------
        val pushKey = rsaKey(1024)
        val pushCsr = AlbertCsr.create(pushKey)
        val activationInfo = AlbertActivationInfo(
            activationRandomness = "A1B2C3D4-E5F6-4A1B-8C2D-9E0F1A2B3C4D",
            buildVersion = identifiers.osBuildNumber!!,
            deviceCertRequestPem = pushCsr.pem,
            productType = identifiers.productName!!,
            productVersion = export.macOsProductVersion!!,
            serialNumber = identifiers.serialNumber,
            uniqueDeviceId = export.deviceId!!,
        )
        val albert = AlbertActivator(env).activate(activationInfo) // default = the bundled FairPlay signer
        assertEquals(1, env.albertActivations)
        val deviceCertDer = Pem.decode(requireNotNull(albert.deviceCertificatePem), Pem.CERTIFICATE_TYPE)
        assertContentEquals(env.deviceCertDer, deviceCertDer)

        store.updateAccount { account ->
            account.copy(pushCertDer = deviceCertDer, pushCertChainJson = pushCertChainJson(listOf(deviceCertDer)))
        }

        // ------------------------------------------------------------------
        // 5. GSA login (§1.5) → 2FA → PET → delegate sign-in → IDS credentials.
        // ------------------------------------------------------------------
        val deviceConfig = GsaHeaderConfig(
            hardwareModel = identifiers.productName!!,
            osName = "macOS",
            osVersion = export.macOsProductVersion!!,
            osBuild = identifiers.osBuildNumber!!,
        )
        val cpd = GsaCpd(anisette = anisette, keychainIdentifier = ByteArray(16) { (it + 1).toByte() })
        val chain = GsaLoginChain(
            http = env,
            cpd = { cpd },
            credentialStore = IdsStoreGsaCredentials(store),
            twoFactorHeaders = { GsaTwoFactorHeaders.of(cpd, device = deviceConfig) },
            headerConfig = deviceConfig,
            clock = { now },
            logEvent = {},
        )

        val required = chain.login(username, password) as GsaLoginResult.SecondaryAuthRequired
        assertEquals(GsaStatus.AU_TRUSTED_DEVICE, required.variant)
        assertEquals(gsaIdentityToken(env.adsid, "idms-token-1"), required.identityToken)
        assertEquals(1, env.gsaInitCount)
        assertEquals(1, env.gsaCompleteCount)

        // The push fires when the login surfaces the 2FA prompt (the caller's job — the
        // UI shows ENTER CODE only after the devices were pinged); completeSecondaryAuth
        // validates only (a second trigger invalidates the first code — observed live).
        chain.triggerTrustedDevicePush(required.variant, required.identityToken!!)
        val authenticated = chain.completeSecondaryAuth(
            username = username,
            passwordHash = passwordHash,
            variant = GsaStatus.AU_TRUSTED_DEVICE,
            identityToken = required.identityToken!!,
            securityCode = env.securityCode,
        ) as GsaLoginResult.Authenticated
        // §1.5: the SRP login runs a SECOND time after 2FA, completing as logged-in.
        assertEquals(2, env.gsaInitCount)
        assertEquals(2, env.gsaCompleteCount)
        assertEquals(1, env.trustedDeviceTriggers)
        assertEquals(1, env.validateCount)
        assertEquals(env.securityCode, env.validateSecurityCode)
        assertEquals("pet-3", authenticated.pet!!.token)

        // The PET (+ username, hash, adsid) is persisted through the store adapter.
        val accountAfterLogin = store.account()!!
        assertEquals(username, accountAfterLogin.gsaUsername)
        assertContentEquals(passwordHash, accountAfterLogin.gsaPasswordHash)
        assertEquals(env.adsid, accountAfterLogin.gsaAdsId)
        assertEquals("pet-3", accountAfterLogin.gsaPetToken)
        // No token-header trailer → the recorded 300 s default (§1.5).
        assertEquals(now + 300_000, accountAfterLogin.gsaPetExpiresAtEpochMs)
        // The session gate's silent-PET path serves the stored token with no network.
        assertEquals("pet-3", chain.petToken(now + 100_000))
        assertEquals(2, env.gsaInitCount)

        // The delegate sign-in consumes the step-3 blob — wire it for the server-side assertion.
        env.expectedValidationBlob = validation.blob
        val credentials = chain.idsDelegateCredentials(
            username = username,
            pet = authenticated.pet!!.token,
            adsid = authenticated.spd!!.adsid!!,
            validationData = validation.blob,
            anisette = anisette,
        )
        assertEquals(1, env.signInCount)
        assertEquals(username, env.delegateUsername)
        assertEquals("pet-3", env.delegatePet) // Basic username:PET (§1.5)
        assertEquals(env.authToken, credentials.authToken)
        assertEquals(env.profileId, credentials.profileId)

        // The GSA postdata liveness event fires AFTER the delegate sign-in (rev 26 order —
        // sign-in first, postdata after; the sign-in mints its own Nas-Qualify blob), with a
        // FRESH anisette set and the spd's com.apple.gs.idms.hb token.
        GsaPostdataClient(env).post(
            GsaPostdataRequest(
                adsid = env.adsid,
                hbToken = authenticated.spd!!.tokens[GsaSpd.SERVICE_IDMS_HB]!!.token,
                anisette = anisette,
                clientInfo = deviceConfig.clientInfo,
            ),
        )
        assertEquals(1, env.postdataCount)
        val signInIndex = env.callUrls().indexOfFirst { it == GsaDelegateLoginClient.SIGNIN_ENDPOINT }
        val postdataIndex = env.callUrls().indexOfFirst { it == GsaPostdataClient.ENDPOINT }
        assertTrue(signInIndex in 0 until postdataIndex, "postdata must come after the delegate sign-in (rev 26)")

        store.updateAccount { account ->
            account.copy(
                delegateAuthToken = credentials.authToken,
                delegateProfileId = credentials.profileId,
                delegateRefreshedAtEpochMs = now,
            )
        }

        // ------------------------------------------------------------------
        // 6. Authenticate (§1.2) → identity certificate → register (§1.4).
        // ------------------------------------------------------------------
        val bag = bagFetcher.idsBag()
        val authKey = rsaKey(2048)
        val realmCn = IdsCsrBuilder.realmUserIdCn(credentials.profileId)
        val authCsr = IdsCsrBuilder.create(authKey, realmCn)
        env.expectedCsrDer = authCsr.der

        val authResponse = chain.authenticateIds(
            credentials = credentials,
            bagKey = IdsAuthenticator.BAG_KEY_DS_ID,
            csrDer = authCsr.der,
            authenticator = IdsAuthenticator(env, bag, protocolVersion = "1640", userAgent = IDS_USER_AGENT),
        )
        assertEquals(1, env.authenticateCount)
        assertEquals(0, authResponse.status)
        assertContentEquals(env.identityCertDer, authResponse.cert)

        val pushToken = ByteArray(32) { (it + 3).toByte() } // courier connect-ack token (§3.3) — structural here
        val user = RegisterUser(
            userId = credentials.profileId,
            uris = listOf(mapOf("uri" to env.registeredUri)), // the server-echoed handle list (§1.4)
            tag = null,
            authKey = authKey.private,
            authCertificateDer = requireNotNull(authResponse.cert),
            clientData = mapOf("client-data-version" to 2L),
            ktLoggableData = null,
        )
        val registerBody = RegisterBody(
            deviceName = "Light Phone III",
            hardwareVersion = identifiers.productName!!,
            language = "en-US",
            osVersion = export.macOsProductVersion!!,
            softwareVersion = "1.0",
            privateDeviceData = PrivateDeviceData(
                osBuild = identifiers.osBuildNumber!!,
                platformName = identifiers.productName!!,
                osVersion = export.macOsProductVersion!!,
                deviceUuid = export.deviceId!!,
                appleEpochSeconds = now / 1000 - APPLE_EPOCH_OFFSET_SECONDS,
            ),
            services = listOf(RegisterService(RegisterService.MADRID, users = listOf(user))),
            validationData = validation.blob,
        )
        val registerResponse = IdsRegistrar(
            env,
            bag,
            RegisterConfig(
                pushToken = pushToken,
                pushKey = pushKey.private,
                pushCertificateDer = deviceCertDer,
                protocolVersion = "1640",
                userAgent = IDS_USER_AGENT,
            ),
        ).register(registerBody)
        assertEquals(1, env.registerCount)
        assertEquals(0, registerResponse.status)
        val registeredService = registerResponse.services.single()
        assertEquals(RegisterService.MADRID, registeredService.service)
        assertEquals(0, registeredService.status)
        val registeredUser = registeredService.users.single()
        assertEquals(env.profileId, registeredUser.userId)
        assertEquals(0, registeredUser.status)
        assertEquals(86400L, registeredUser.nextHbi)
        assertContentEquals(env.identityCertDer, registeredUser.cert)
        assertEquals(listOf(IdsRegisterUriResult(env.registeredUri, 0)), registeredUser.uris)

        // §1.4 register signature sets verify over the recorded tuple (bag key, query, body, push token).
        val registerCall = env.registerCalls.single()
        val signingFields = listOf(
            IdsRegistrar.BAG_KEY.toByteArray(Charsets.UTF_8),
            ByteArray(0),
            registerCall.body,
            pushToken,
        )
        verifyRegisterSignature(registerCall, "x-push-nonce", "x-push-sig", pushKey, signingFields)
        verifyRegisterSignature(registerCall, "x-auth-nonce-0", "x-auth-sig-0", authKey, signingFields)
        assertEquals(Base64.getEncoder().encodeToString(deviceCertDer), registerCall.headers["x-push-cert"])
        assertEquals(Base64.getEncoder().encodeToString(pushToken), registerCall.headers["x-push-token"])
        assertEquals(Base64.getEncoder().encodeToString(authResponse.cert), registerCall.headers["x-auth-cert-0"])
        assertEquals("1640", registerCall.headers["x-protocol-version"])

        store.recordRegistration(
            idsRegisteredUser(
                userId = registeredUser.userId!!,
                status = registeredUser.status,
                identityCertDer = requireNotNull(registeredUser.cert),
                uris = registeredUser.uris.map { it.uri },
                registeredAtEpochMs = now,
                authCertDer = authResponse.cert,
                nextHbiSeconds = registeredUser.nextHbi,
            ),
        )
        store.updateAccount { account ->
            account.copy(
                lastRegistrationEpochMs = now,
                macSerial = identifiers.serialNumber,
                macModel = identifiers.productName,
                macBoardId = identifiers.boardId,
                macUuid = identifiers.platformUuid,
                macMlb = identifiers.logicBoardSerial,
                macRom = identifiers.rom.joinToString("") { "%02x".format(it) },
                macBuild = identifiers.osBuildNumber,
            )
        }

        // ------------------------------------------------------------------
        // 7. The store's end state — everything the engine's session gate needs.
        // ------------------------------------------------------------------
        val finalAccount = store.account()!!
        // Provisioned ADI state.
        assertEquals(now, finalAccount.adiProvisionedAtEpochMs)
        val storedTokens = requireNotNull(adiMachineTokensRaw(finalAccount.adiMachineTokensPlist))
        assertContentEquals(machineIdentifier, storedTokens["machine-identifier"] as ByteArray)
        // GSA login state: PET + hash + adsid (never the raw password).
        assertEquals("pet-3", finalAccount.gsaPetToken)
        assertEquals(now + 300_000, finalAccount.gsaPetExpiresAtEpochMs)
        assertEquals(env.adsid, finalAccount.gsaAdsId)
        assertContentEquals(passwordHash, finalAccount.gsaPasswordHash)
        // Delegate tokens from the sign-in.
        assertEquals(env.authToken, finalAccount.delegateAuthToken)
        assertEquals(env.profileId, finalAccount.delegateProfileId)
        // The device (push) certificate from albert.
        assertContentEquals(deviceCertDer, finalAccount.pushCertDer)
        // Registered user row: identity cert, auth cert, URIs, next-hbi.
        val users = store.registeredUsers()
        assertTrue(users.isNotEmpty(), "the session gate needs registered users to exist")
        assertEquals(1, users.size)
        val userRow = users.single()
        assertEquals(env.profileId, userRow.userId)
        assertEquals(0, userRow.status)
        assertContentEquals(env.identityCertDer, userRow.identityCertDer)
        assertContentEquals(authResponse.cert, userRow.authCertDer)
        assertEquals(listOf(env.registeredUri), registeredUserUris(userRow))
        assertEquals(86400L, userRow.nextHbiSeconds)
        assertEquals(now, userRow.registeredAtEpochMs)
        assertTrue(userRow.identityCertNotAfterEpochMs > now, "store parses the identity cert's notAfter")
    }

    @Test
    fun `the fake environment fails loudly when a hop does not carry the recorded shape`() = runBlocking {
        val env = DryRunAppleEnvironment(passwordHash)
        val bagFetcher = IdsBagFetcher(env)
        val validation = ValidationDataExchange(env, bagFetcher, logEvent = {})
            .generate(exportIdentifiers(), nowEpochMs = 1_770_000_000_000L)

        val deviceConfig = GsaHeaderConfig(
            hardwareModel = "MacBookPro18,3", osName = "macOS", osVersion = "13.4", osBuild = "22G74",
        )
        val chain = GsaLoginChain(
            http = env,
            cpd = { GsaCpd(anisette = anisetteHeaders(), keychainIdentifier = ByteArray(16)) },
            twoFactorHeaders = {
                GsaTwoFactorHeaders.of(
                    GsaCpd(anisette = anisetteHeaders(), keychainIdentifier = ByteArray(16)),
                    device = deviceConfig,
                )
            },
            headerConfig = deviceConfig,
            clock = { 1_770_000_000_000L },
        )
        val required = chain.login(username, password) as GsaLoginResult.SecondaryAuthRequired
        chain.completeSecondaryAuth(username, passwordHash, required.variant, required.identityToken!!, env.securityCode)

        // A tampered blob cannot sneak past the server-side X-Mme-Nas-Qualify assertion:
        // wire a WRONG blob and the fake fails loudly on the unrecorded-shape hop.
        env.expectedValidationBlob = byteArrayOf(9, 9, 9)
        val exception = assertFailsWith<IllegalArgumentException> {
            chain.idsDelegateCredentials(
                username = username,
                pet = "pet-3",
                adsid = env.adsid,
                validationData = byteArrayOf(1, 2, 3), // not the blob the register/qualify sinks carry
                anisette = anisetteHeaders(),
            )
        }
        assertTrue(exception.message!!.contains("X-Mme-Nas-Qualify"))
        Unit
    }

    // ---- helpers ----

    private fun adiUrl(phase: String) = "https://${AdiProvisioner.GSA_HOST}/adi/$phase-provisioning"

    private fun rsaKey(bits: Int): KeyPair =
        KeyPairGenerator.getInstance("RSA").apply { initialize(bits) }.generateKeyPair()

    /** §1.4's indexed signature sets: 17-byte nonce, 0x01 0x01-prefixed RSA-SHA1 signature. */
    private fun verifyRegisterSignature(
        call: DryRunAppleEnvironment.RegisterCall,
        nonceHeader: String,
        sigHeader: String,
        key: KeyPair,
        fields: List<ByteArray>,
    ) {
        val nonce = Base64.getDecoder().decode(call.headers.getValue(nonceHeader))
        assertEquals(17, nonce.size)
        assertEquals(0x01, nonce[0].toInt())
        val signature = Base64.getDecoder().decode(call.headers.getValue(sigHeader))
        assertContentEquals(byteArrayOf(0x01, 0x01), signature.copyOfRange(0, 2))
        val verifier = Signature.getInstance("SHA1withRSA")
        verifier.initVerify(key.public)
        verifier.update(IdsSigning.signingBytes(nonce, fields))
        assertTrue(verifier.verify(signature.copyOfRange(2, signature.size)), "$sigHeader does not verify")
    }

    private fun anisetteHeaders() = mapOf(
        "X-Apple-I-Client-Time" to "2026-02-04T12:00:00Z",
        "X-Apple-I-TimeZone" to "UTC",
        "X-Apple-Locale" to "en_US",
        "X-Apple-I-MD-RINFO" to "17106176",
        "X-Mme-Device-Id" to "6a7d4e10-9c2b-4f11-8a33-0d5e1f2a3b4c",
        "X-Apple-I-MD" to Base64.getEncoder().encodeToString("dry-run-otp".toByteArray()),
        "X-Apple-I-MD-M" to Base64.getEncoder().encodeToString(ByteArray(32) { (it + 0x11).toByte() }),
        "X-Apple-I-MLB" to "MLB-DRYRUN-STRING",
        "X-Apple-I-ROM" to ROM.joinToString("") { "%02x".format(it) },
        "X-Apple-I-SRL-NO" to "C02DRYRUNMAC",
    )

    private fun exportIdentifiers() = MacHardwareInfoExportCode.parsePayload(exportPayload(flag = 0)).identifiers

    // ---- hand-built export-code fixture (the MacHardwareInfoExportTest protobuf encoder pattern) ----

    private object TestProto {
        fun varint(value: Long): ByteArray {
            var v = value
            val out = ArrayList<Byte>()
            while (true) {
                if (v and 0x7f.inv() == 0L) {
                    out.add(v.toByte())
                    return out.toByteArray()
                }
                out.add(((v and 0x7f) or 0x80).toByte())
                v = v ushr 7
            }
        }

        fun message(vararg fields: ByteArray): ByteArray {
            val size = fields.sumOf { it.size }
            return ByteArray(size).also { buffer ->
                var at = 0
                fields.forEach { it.copyInto(buffer, at); at += it.size }
            }
        }

        private fun tag(number: Int, wireType: Int): ByteArray = varint((number.toLong() shl 3) or wireType.toLong())

        fun stringField(number: Int, value: String): ByteArray =
            lenDelimited(number, value.toByteArray(Charsets.UTF_8))

        fun bytesField(number: Int, value: ByteArray): ByteArray = lenDelimited(number, value)

        fun varintField(number: Int, value: Long): ByteArray = tag(number, 0) + varint(value)

        private fun lenDelimited(number: Int, payload: ByteArray): ByteArray =
            tag(number, 2) + varint(payload.size.toLong()) + payload
    }

    private fun identifierMessage(): ByteArray = TestProto.message(
        TestProto.stringField(1, "MacBookPro18,3"),
        TestProto.bytesField(2, MAC_ADDRESS),
        TestProto.stringField(3, "C02DRYRUNMAC"),
        TestProto.stringField(4, "PLATFORM-UUID-DRYRUN"),
        TestProto.stringField(5, "ROOT-DISK-UUID-DRYRUN"),
        TestProto.stringField(6, "Mac-BBAA2211FFEE0011"),
        TestProto.stringField(7, "22G74"),
        TestProto.bytesField(8, byteArrayOf(1, 2, 3)),
        TestProto.bytesField(9, byteArrayOf(4, 5)),
        TestProto.bytesField(10, byteArrayOf(6)),
        TestProto.bytesField(11, ROM),
        TestProto.bytesField(12, byteArrayOf(7, 8, 9, 10)),
        TestProto.stringField(13, "MLB-DRYRUN-STRING"),
        TestProto.bytesField(14, byteArrayOf(11, 12)),
    )

    private fun exportPayload(flag: Int): ByteArray {
        val outer = TestProto.message(
            TestProto.bytesField(1, identifierMessage()),
            TestProto.stringField(2, "13.4"),
            TestProto.varintField(3, 1640L),
            TestProto.stringField(4, "6a7d4e10-9c2b-4f11-8a33-0d5e1f2a3b4c"),
            TestProto.stringField(5, "iCloudHelper/282 (dry-run)"),
            TestProto.stringField(6, "AOSKit/282 (dry-run)"),
        )
        return "OABS".toByteArray(Charsets.US_ASCII) + byteArrayOf(flag.toByte()) + outer
    }

    companion object {
        private val MAC_ADDRESS = byteArrayOf(0xA1.toByte(), 0xB2.toByte(), 0xC3.toByte(), 0x01, 0x02, 0x03)
        private val ROM = byteArrayOf(0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F)

        /** The recorded §1.5 sign-in/IDS user-agent family (§1.4: `com.apple.invitation-registration […]`). */
        private const val IDS_USER_AGENT = "com.apple.invitation-registration [macOS,13.4,22G74,MacBookPro18,3]"

        /** The ADI provisioning content type is unrecorded (C6) — structural. */
        private const val PROVISIONING_CONTENT_TYPE = "text/x-xml-plist"

        /** Seconds between the 2001-01-01 Apple epoch and the 1970 unix epoch (§1.4 `d`). */
        private const val APPLE_EPOCH_OFFSET_SECONDS = 978_307_200L
    }
}
