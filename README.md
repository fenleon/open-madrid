# Open Madrid

An open implementation of Apple's madrid protocol (iMessage) in Kotlin: the binary plist codecs, the APNs "courier" push client, the IDS identity service, the encryption envelopes, the registration/activation chain, and the ADI anisette chain (device provisioning, OTP headers, the validation-stamp mint) — all computed locally, in the open. Apache-2.0. [open-absinthe](https://github.com/JJTech0130/open-absinthe), the reference everyone else depends on, is a mock placeholder with no real code; this is the real thing.

## Status

Verified against Apple:

- **Registration** — Albert activation, full GSA sign-in (SRP, trusted-device 2FA, PET delivery), IDS authenticate and register all ran live (2026-10-02→04); the registered handle stayed active.
- **Bags and TLS** — both bag endpoints return plists these parsers handle; certificate pinning validates Apple's real chains. A drift check ships with the repo (`:engine:runProbe`).
- **ADI/anisette** — the white-box ciphers, the GSA provisioning exchange, the spim/cpim/ptm wire framing, and the validation-stamp ("NAC") mint are reimplemented in Kotlin, clean-room, byte-exact against live captures. The full 517-byte stamp computes from its inputs; `NacMint` is the public facade. No anisette server, no Unicorn, no Mac relay.
- **The validation endpoint's `5003 EM` error is solved** (spec rev 38): it fingerprints the TLS handshake and only accepts rustls-shaped clients. Proven by posting fresh, never-seen blobs minted by the reference client itself — accepted over rustls, rejected byte-for-byte identically over OpenSSL, BoringSSL, and the JVM stacks. Kotlin code and framing were never wrong. JVM consumers need a small rust transport (reqwest + rustls, two functions) for the two validation calls; the private imessage tool in this org carries the reference implementation.

Not yet:

- No message send or receive over the courier; renewal across sessions untested.
- Crypto envelopes have round-trip tests but no known-answer vectors from a live device.
- A few wire details are capture-bound guesses, tracked in the spec's open-questions checklist.
- PQ3 unsupported.

## Why another project?

Almost every route to iMessage is closed in some way:

| Project | License / catch |
|---|---|
| rustpush | SSPL |
| pypush | SSPL |
| imessagego | AGPL |
| BlueBubbles | Needs a Mac running 24/7 |
| OpenBubbles | Depends on closed-source open-absinthe |

The protocol facts behind the code are written up in the spec: [docs/imessage-protocol-spec.md](docs/imessage-protocol-spec.md).

## Contributing

This is a clean-room. Contributors never read the source of rustpush, pypush, imessagego, or their forks. Two roles, kept apart:

1. Readers study the existing projects. Their only output is the spec.
2. Writers work only from the spec, Apple's documentation, and recordings of their own device's traffic.

This keeps the code fully open and acceptable to F-Droid and other distribution channels.

## Apple material

No Apple-derived code or binary ships here, including the IMDAppleServices framework. The bundled identity in `registration/src/main/resources/imessage/fairplay/` is a synthetic placeholder, generated and self-signed, for tests only; live activation requires each user to stage Apple's real FairPlay identity themselves.

One documented exception: the ClearADI and pear lookup tables (constant data the ADI ciphers need) were reconstructed by analyzing a compiled ADI implementation and ship as generated Kotlin source, decoded at startup. No Apple code, binary, or resource file is committed. The extraction method is in the spec.

## Building

```bash
./gradlew build             # all modules + tests
./gradlew :engine:runProbe  # live drift check
```

## License

[Apache-2.0](LICENSE).

Support my work on [Ko-fi](https://ko-fi.com/fenleon) or [GitHub Sponsors](https://github.com/sponsors/fenleon).
