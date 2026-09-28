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
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * JVM software stand-in for [AndroidKeystoreKeyPairs] — the AndroidKeyStore provider does not
 * exist on the JVM, so the seam's contract (get-or-create per alias) is what is tested here.
 */
class SoftwareKeyPairs : IdsKeyPairs {
    private val cache = HashMap<String, KeyPair>()
    override fun getOrCreate(alias: String, spec: IdsKeySpec): KeyPair = cache.getOrPut(alias) {
        when (spec) {
            is IdsKeySpec.Rsa -> KeyPairGenerator.getInstance("RSA").apply { initialize(spec.bits) }.generateKeyPair()
            IdsKeySpec.Ec -> KeyPairGenerator.getInstance("EC").apply {
                initialize(ECGenParameterSpec("secp256r1"))
            }.generateKeyPair()
        }
    }
}

class IdsKeysTest {

    @Test
    fun createMintsTheRecordedKeySet() {
        val keys = IdsKeys.create(SoftwareKeyPairs(), "user-1")

        assertEquals(2048, (keys.push.public as RSAPublicKey).modulus.bitLength())
        assertEquals(2048, (keys.auth.public as RSAPublicKey).modulus.bitLength())
        assertEquals(1280, (keys.identityEncryption.public as RSAPublicKey).modulus.bitLength())
        assertEquals("EC", keys.identitySigning.public.algorithm)
        assertEquals("EC", keys.device.public.algorithm)
        assertEquals("EC", keys.prekey.public.algorithm)
        for (ec in listOf(keys.identitySigning, keys.device, keys.prekey)) {
            assertEquals("EC", ec.public.algorithm)
        }
    }

    @Test
    fun getOrCreateIsIdempotentPerAlias() {
        val keyPairs = SoftwareKeyPairs()
        val first = keyPairs.getOrCreate(IdsKeys.PUSH_ALIAS, IdsKeySpec.Rsa(bits = 2048))
        val second = keyPairs.getOrCreate(IdsKeys.PUSH_ALIAS, IdsKeySpec.Rsa(bits = 2048))
        assertSame(first, second)
    }

    @Test
    fun authAliasIsStablePerUserAndDistinctAcrossUsers() {
        assertEquals(IdsKeys.authAlias("user-1"), IdsKeys.authAlias("user-1"))
        assertTrue(IdsKeys.authAlias("user-1") != IdsKeys.authAlias("user-2"))
        assertTrue(IdsKeys.authAlias("user-1").startsWith("ids-auth-"))
        assertTrue(!IdsKeys.authAlias("+15551234567").contains("+"))
    }

    @Test
    fun activationKeysSignThroughIdsSigning() {
        val keys = IdsKeys.create(SoftwareKeyPairs(), "user-1")
        val nonce = IdsSigning.nonce()
        val fields = listOf(byteArrayOf(1), ByteArray(0), byteArrayOf(2), ByteArray(3))

        val signature = IdsSigning.sign(keys.push.private, nonce, fields)

        val verifier = Signature.getInstance("SHA1withRSA")
        verifier.initVerify(keys.push.public)
        verifier.update(IdsSigning.signingBytes(nonce, fields))
        assertTrue(verifier.verify(signature.copyOfRange(2, signature.size)))
    }
}
