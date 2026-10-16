package dev.fenn.imessage.registration

import dev.fenn.imessage.codec.Plist
import dev.fenn.imessage.codec.stringKeyedDictOrNull
import java.security.KeyPair
import java.security.KeyPairGenerator
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse

/**
 * Structural parity of the §1.4 register body against the shipped reference's captured one.
 *
 * The fixture is a shape-only projection of `captures/c56k/ob-trap-20261014-201103/frame-026.bin`
 * (gzip → 13301 B XML plist, sha256 recorded in the fixture): service order, capability records,
 * sub-service lists, key sets, `ec-version` values and the identity-blob lengths. The reference
 * user's identifying values (device-name, os-version, user-id, uris, the key bytes themselves,
 * validation-data) are deliberately absent — this is a public repo.
 */
class RegisterServiceCatalogTest {

    private val shape: Map<String, Any?> = Plist.parse(
        checkNotNull(javaClass.getResourceAsStream("/imessage/register-reference-shape.plist")) {
            "fixture /imessage/register-reference-shape.plist missing"
        }.readBytes(),
    ).let { stringKeyedDictOrNull(it) ?: error("fixture is not a dict") }

    private val capturedServices: List<Map<String, Any?>> =
        (shape["services"] as List<*>).mapIndexed { i, entry ->
            stringKeyedDictOrNull(entry) ?: error("fixture services[$i] is not a dict")
        }

    private val identity = MadridIdentity.generate()

    private val handleUris = listOf(
        mapOf("uri" to "tel:+15557654321"),
        mapOf("uri" to "mailto:user@example.com"),
    )

    private fun services() = RegisterServiceCatalog.services(
        identity = identity,
        prekeyTimestampEpochSeconds = 1_760_000_000L,
        userId = "D:10000000000",
        uris = handleUris,
        authKey = AUTH.private,
        authCertificateDer = byteArrayOf(0x30, 0x01),
    )

    @Test
    fun catalogIsTheCapturedFourServicesInTheCapturedOrder() {
        assertEquals(capturedServices.map { it["service"] }, RegisterServiceCatalog.ALL.map { it.service })
        assertEquals(
            listOf(
                "com.apple.madrid",
                "com.apple.private.alloy.multiplex1",
                "com.apple.private.alloy.facetime.multi",
                "com.apple.ess",
            ),
            services().map { it.service },
        )
    }

    @Test
    fun everyServiceCarriesTheCapturedCapabilitiesAndSubServices() {
        val built = services()
        capturedServices.forEachIndexed { i, captured ->
            val expected = captured["capabilities"] as List<*>
            assertEquals(expected.size, built[i].capabilities.size, "services[$i] capability count")
            expected.forEachIndexed { j, entry ->
                val cap = stringKeyedDictOrNull(entry) ?: error("fixture capability is not a dict")
                assertEquals(cap["flags"], built[i].capabilities[j].flags.toLong(), "services[$i].capabilities[$j].flags")
                assertEquals(cap["name"], built[i].capabilities[j].name, "services[$i].capabilities[$j].name")
                assertEquals(cap["version"], built[i].capabilities[j].version.toLong())
            }
            assertEquals(captured["sub-services"], built[i].subServices, "services[$i] sub-services")
        }
    }

    @Test
    fun everyUserCarriesTheCapturedKeysAndEcVersion() {
        val built = services()
        capturedServices.forEachIndexed { i, captured ->
            val dict = built[i].toDict()
            val user = (dict["users"] as List<*>).single() as Map<*, *>
            assertEquals(captured["user-keys"], user.keys.toList(), "services[$i] user keys")
            val clientData = user["client-data"] as Map<*, *>
            assertEquals(
                (captured["client-data-keys"] as List<*>).toSet(),
                clientData.keys.toSet(),
                "services[$i] client-data keys",
            )
            assertEquals(captured["ec-version"], clientData["ec-version"], "services[$i] ec-version")
            // Identity keys open the dict, in the reference's order, before the capability keys.
            assertEquals(
                listOf(
                    "public-message-identity-key", "public-message-identity-version", "ec-version",
                    "public-message-identity-ngm-version", "public-message-ngm-device-prekey-data-key",
                    "kt-version",
                ),
                clientData.keys.take(6).toList(),
            )
        }
    }

    @Test
    fun everyServiceSharesOneIdentityAndTheCapturedBlobSizes() {
        val built = services()
        val identities = built.map { (((it.toDict()["users"] as List<*>).single() as Map<*, *>)["client-data"] as Map<*, *>)["public-message-identity-key"] as ByteArray }
        val prekeys = built.map { (((it.toDict()["users"] as List<*>).single() as Map<*, *>)["client-data"] as Map<*, *>)["public-message-ngm-device-prekey-data-key"] as ByteArray }
        val ktData = built.map { ((it.toDict()["users"] as List<*>).single() as Map<*, *>)["kt-loggable-data"] as ByteArray }

        identities.drop(1).forEach { assertContentEquals(identities.first(), it, "identity key differs per service") }
        prekeys.drop(1).forEach { assertContentEquals(prekeys.first(), it, "prekey data differs per service") }
        ktData.drop(1).forEach { assertContentEquals(ktData.first(), it, "kt-loggable-data differs per service") }

        capturedServices.forEachIndexed { i, captured ->
            assertEquals(captured["identity-key-bytes"], identities[i].size.toLong(), "services[$i] identity key size")
            assertEquals(captured["prekey-data-bytes"], prekeys[i].size.toLong(), "services[$i] prekey size")
            assertEquals(captured["kt-loggable-data-bytes"], ktData[i].size.toLong(), "services[$i] kt size")
        }
    }

    @Test
    fun theSameHandleListRidesOnEveryServiceAndTheUserIdIsVerbatim() {
        services().forEach { service ->
            val user = (service.toDict()["users"] as List<*>).single() as Map<*, *>
            assertEquals(handleUris, user["uris"], "${service.service} uris")
            assertEquals("D:10000000000", user["user-id"], "${service.service} user-id")
            assertFalse(user.containsKey("tag"), "the DS:ID flow has no SIM tag")
        }
    }

    @Test
    fun bodyTopLevelKeysAndPrivateDeviceDataKeysMatchTheCapture() {
        val body = RegisterBody(
            deviceName = "LP3",
            hardwareVersion = "h",
            language = "en-US",
            osVersion = "o",
            softwareVersion = "s",
            privateDeviceData = PrivateDeviceData(
                osBuild = "b",
                platformName = "p",
                osVersion = "o",
                deviceUuid = "abcd-ef",
                appleEpochSeconds = 800_000_000L,
            ),
            services = services(),
            validationData = byteArrayOf(1),
        ).toDict()
        assertEquals(shape["top-level-keys"], body.keys.toList())
        assertEquals(
            (shape["private-device-data-keys"] as List<*>),
            (body["private-device-data"] as Map<*, *>).keys.toList(),
        )
    }

    private companion object {
        // 1024-bit test key, per the IdsActivationTest precedent — never hardcoded key material.
        val AUTH: KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair()
    }
}
