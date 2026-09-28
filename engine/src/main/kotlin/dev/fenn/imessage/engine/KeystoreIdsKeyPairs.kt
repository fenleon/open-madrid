package dev.fenn.imessage.engine

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import dev.fenn.imessage.registration.IdsKeyPairs
import dev.fenn.imessage.registration.IdsKeySpec
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec

/**
 * AndroidKeyStore-backed [IdsKeyPairs]: keys are generated and held inside the keystore —
 * callers get signing/decryption handles and public keys, never key material (§1.4: private
 * keys are generated and stored locally and never leave the device).
 *
 * Digest/padding sets are the narrowest covering the recorded constructions: SHA-1-PKCS1
 * for the §1.4 RSA signatures, SHA-1-OAEP for the §4.2 transport block, SHA-256 for the
 * §4.3 ECDSA. Keys are generated once per alias and reused ([IdsKeys.create]'s contract —
 * re-registration does not mint new keys, §6.1); AndroidKeyStore issues the self-signed
 * attestation certificate itself, so no certificate material is built here (a CSR-capable
 * certificate chain export, if the app shell ever needs one, is a later concern — the
 * registration seam consumes [KeyPair]s only).
 *
 * JVM unit tests cannot touch AndroidKeyStore — this class is intentionally thin and gets
 * verification in the app-shell/emulator step; the software stand-in lives in :registration's
 * tests.
 */
class KeystoreIdsKeyPairs(
    private val provider: String = "AndroidKeyStore",
) : IdsKeyPairs {

    override fun getOrCreate(alias: String, spec: IdsKeySpec): KeyPair {
        val store = KeyStore.getInstance(provider).apply { load(null) }
        (store.getEntry(alias, null) as? KeyStore.PrivateKeyEntry)?.let { entry ->
            return KeyPair(entry.certificate.publicKey, entry.privateKey)
        }
        return when (spec) {
            is IdsKeySpec.Rsa -> generate(alias, "RSA", rsaSpec(alias, spec))
            is IdsKeySpec.Ec -> generate(alias, "EC", ecSpec(alias))
        }
    }

    private fun generate(alias: String, algorithm: String, keySpec: KeyGenParameterSpec): KeyPair {
        val generator = KeyPairGenerator.getInstance(algorithm, provider)
        generator.initialize(keySpec)
        return generator.generateKeyPair()
    }

    private fun rsaSpec(alias: String, spec: IdsKeySpec.Rsa): KeyGenParameterSpec {
        val purposes = if (spec.forEncryption) {
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        } else {
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        }
        val builder = KeyGenParameterSpec.Builder(alias, purposes).setKeySize(spec.bits)
        return if (spec.forEncryption) {
            builder.setDigests(KeyProperties.DIGEST_SHA1)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .build()
        } else {
            builder.setDigests(KeyProperties.DIGEST_SHA1)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .build()
        }
    }

    private fun ecSpec(alias: String): KeyGenParameterSpec =
        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .build()
}
