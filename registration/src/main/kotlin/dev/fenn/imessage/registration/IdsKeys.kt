package dev.fenn.imessage.registration

import java.security.KeyPair
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec

/** What a key is for, in keystore-generation terms (spec §1.4/§1.2). */
sealed interface IdsKeySpec {

    /**
     * RSA key. Signing keys (push §1.4, auth §1.2 — 2048) sign with SHA-1-PKCS1v1.5
     * ([IdsSigning]); the identity encryption key (§1.4 — 1280) decrypts the legacy pair
     * envelope's RSA-OAEP transport block (§4.2).
     */
    data class Rsa(val bits: Int, val forEncryption: Boolean = false) : IdsKeySpec

    /** P-256 EC key: identity signing, device key, pre-key (§1.4). */
    data object Ec : IdsKeySpec
}

/**
 * Key-pair seam. Production holds keys in the Android Keystore (the originating repo's
 * `AndroidKeystoreKeyPairs`, not ported — see the port note below) so private keys never
 * leave secure hardware; tests use a software implementation because the AndroidKeyStore
 * provider does not exist on the JVM.
 *
 * Keys are generated once per alias and reused ([getOrCreate]); rotation (renewal, pre-key
 * refresh — spec §6.1) is a later component's policy decision and can be expressed as a new
 * alias + eventual deletion, nothing here hardcodes a lifetime.
 */
interface IdsKeyPairs {
    fun getOrCreate(alias: String, spec: IdsKeySpec): KeyPair
}

// Port note: the originating repo's Android Keystore implementation of this seam
// (`AndroidKeystoreKeyPairs`, non-exportable private keys, digest/padding sets covering the
// §1.4 SHA-1-PKCS1 signatures, §4.3 ECDSA-SHA256 and §4.2 OAEP(SHA-1) transport) is Android-
// only and waits for the Android integration; whether a device keystore accepts SHA-1 OAEP
// for the 1280-bit identity encryption key is only verifiable on a real device —
// TODO(device-test).

/** The six key pairs one registration needs (spec §1.2/§1.4/§2.1 "identity keypair"). */
class IdsActivationKeys(
    /** RSA-2048 — signs every IDS request (§1.4); its CSR goes to Albert for the push cert ([AlbertCsr], §1.2). */
    val push: KeyPair,
    /** RSA-2048 — per-user auth key; its CSR (§1.2) is exchanged for the auth certificate. */
    val auth: KeyPair,
    /** RSA-1280 — legacy identity encryption key, decrypts the pair envelope's transport block (§4.2). */
    val identityEncryption: KeyPair,
    /** P-256 — legacy identity signing key. */
    val identitySigning: KeyPair,
    /** P-256 — EC scheme device key (§4.3). */
    val device: KeyPair,
    /** P-256 — EC scheme pre-key (§4.3); rotation on re-registration is a later component's policy. */
    val prekey: KeyPair,
)

object IdsKeys {
    const val PUSH_ALIAS = "ids-push"
    const val IDENTITY_ENCRYPTION_ALIAS = "ids-identity-encryption"
    const val IDENTITY_SIGNING_ALIAS = "ids-identity-signing"
    const val DEVICE_ALIAS = "ids-device"
    const val PREKEY_ALIAS = "ids-prekey"

    /**
     * The auth key is per user (§1.2) — the alias is namespaced by a SHA-1 of the user id so
     * no user-controlled string becomes a keystore alias verbatim.
     */
    fun authAlias(userId: String): String {
        val digest = MessageDigest.getInstance("SHA-1")
            .digest(userId.toByteArray(Charsets.UTF_8))
        return "ids-auth-" + digest.joinToString("") { "%02x".format(it) }
    }

    /** Generates on first call, reuses afterwards — re-registration does not mint new keys (§6.1). */
    fun create(keyPairs: IdsKeyPairs, authUserId: String): IdsActivationKeys = IdsActivationKeys(
        push = keyPairs.getOrCreate(PUSH_ALIAS, IdsKeySpec.Rsa(bits = 2048)),
        auth = keyPairs.getOrCreate(authAlias(authUserId), IdsKeySpec.Rsa(bits = 2048)),
        identityEncryption =
            keyPairs.getOrCreate(IDENTITY_ENCRYPTION_ALIAS, IdsKeySpec.Rsa(bits = 1280, forEncryption = true)),
        identitySigning = keyPairs.getOrCreate(IDENTITY_SIGNING_ALIAS, IdsKeySpec.Ec),
        device = keyPairs.getOrCreate(DEVICE_ALIAS, IdsKeySpec.Ec),
        prekey = keyPairs.getOrCreate(PREKEY_ALIAS, IdsKeySpec.Ec),
    )
}
