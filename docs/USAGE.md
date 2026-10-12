# Using Open Madrid

Open Madrid is a set of plain JVM/Android Kotlin modules. All Apple endpoints are resolved from Apple's own bag files at runtime; nothing is hardcoded beyond the roots the TLS pinning needs.

## Getting it

No Maven repository yet — the fastest route is [JitPack](https://jitpack.io/#fenleon/open-madrid): it builds tagged commits on demand. Pick a tag, then take the modules you need:

```kotlin
repositories { maven("https://jitpack.io") }

dependencies {
    implementation("com.github.fenleon.open-madrid:registration:v0.1.0")
    implementation("com.github.fenleon.open-madrid:engine:v0.1.0")
}
```

Modules: `codec`, `courier`, `crypto`, `ids`, `registration` (plain JVM), `engine` (Android library, the composition root). Vendoring the source works too — every module builds standalone.

## The validation-stamp mint (`registration`)

The NAC stamp is what an Apple validation endpoint wants as proof of hardware identity. Inputs come from the three-step §1.1 exchange (spec §1.1):

```kotlin
// step 2: POST a NacRequestBlob, get session-info back
val pearKey16 = SecureRandom().generateSeed(16)
val blob = NacRequestBlob.build(certChain.last(), pearKey16, SecureRandom())
val sessionInfo = certClient.initializeValidation(blob)

// key establishment + the stamp
val established = NacMint.keyEstablishmentFull(sessionInfo, pearKey16)
val stamp = NacMint.mint(
    cert79 = established.trailing.copyOfRange(0, 79),
    session250 = HardwareConfiguration.from(identifiers).toBin(),
    rngPad = ByteArray(0x17c - 250).also(rng::nextBytes),
    rand16 = ByteArray(16).also(rng::nextBytes),
    body576 = established.payload.copyOfRange(2, 578),
)
```

`identifiers` is a Mac hardware identity — the C58 "Mac-Hardware-Info" export code from a Mac carries all of it (see `MacHardwareInfoExport`).

## Anisette headers (`registration`)

```kotlin
val provider = ClearAnisetteProvider(http, stateStore, loginInfo, rng)
val provisioned = provider.ensureProvisioned()   // live GSA machine provisioning
val headers = provider.anisetteValues(provisioned, System.currentTimeMillis())
```

`http` is any `IdsHttp`. **Important:** Apple's validation endpoint (`identity.ess.apple.com`) rejects every JVM TLS stack by handshake fingerprint — it only accepts rustls-shaped clients. Use a small rust transport (reqwest + rustls, two functions, exposed over UniFFI — see the `ids-bridge` in this org's imessage tool) for the two §1.1 calls. The GSA endpoints accept plain JVM TLS.

## Everything wired together (`engine`)

`Engine` composes the bag fetcher, IDS store, key pairs, HTTP and courier connections over one config:

```kotlin
val engine = Engine(Engine.Config(workingDir = File(context.filesDir, "imessage")))
engine.http          // IdsHttp over the platform stack (pinned Apple roots)
engine.bagFetcher    // IDS + APNs bags
engine.courier()     // the APNs courier connection
```

Registration flows live in the `registration` module: `GsaLoginChain` (Apple-ID sign-in, SRP + 2FA), `GsaCpd`, `GsaDelegateLogin`, `AlbertActivation`, `IdsActivation` — the imessage tool composes them; see its `ImessageRegistration` for a worked end-to-end wiring.

## Support status

See the README and the spec's open-questions checklist. Message send/receive over the courier is not implemented yet.
