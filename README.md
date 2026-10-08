# Open Madrid

An open implementation of Apple's madrid protocol (iMessage) in Kotlin. Covers the property-list codecs, the APNs "courier" push client, the IDS identity service, the encryption envelope, the registration/activation chain, and the ADI anisette chain (device provisioning, per-request OTP headers, and the validation-stamp "NAC" mint) computed fully locally in Kotlin.

Unlike [open-absinthe](https://github.com/JJTech0130/open-absinthe), which is a mock placeholder with no real code, everything here is readable and Apache-2.0 licensed.

## Status

Validated:

- The parsers handle real Apple bytes. The actual 405-entry IDS bag and 65-entry APNs bag, captured from a registered device, are committed as test fixtures and decoded with exact-value assertions.
- The registration chain ran live against Apple (2026-10-02→04, spec rev 26): Albert activation, the packed APNs courier, the full GSA sign-in (SRP, trusted-device 2FA, PET delivery, postdata), then IDS authenticate and register — both green, `mailto:` handle active. The earlier 409 refusals turned out to be Apple's validation-stamp replay guard (one mint = one device record), documented in the spec.
- Two live unauthenticated probes against Apple succeeded: both bag endpoints return plists this stack parses, and certificate pinning validates Apple's real TLS chains. A drift check ships with the repo (`:engine:runProbe`).
- The courier's auth model is settled: the packed path needs no client certificate; the legacy path answers the handshake with a TLS 1.3 post-handshake `certificate_required` alert.
- The ADI anisette chain is reimplemented natively, no emulation or helper binary: the white-box OTP ciphers, the GSA provisioning exchange, the full spim/cpim/ptm wire framing, and the validation-stamp ("NAC") mint — pear white-box cipher, blob assembly, and the 16-byte OTS signature (`NacSign`) — are transcribed clean-room from analysis of a compiled ADI implementation, verified byte-exact against oracle vectors and live captures (three genuine provisioning runs plus a validation-stamp capture under an instrumented debugger). Every byte group of the exchange and of the 517-byte stamp is identified and reproduced; the full stamp computes byte-exact in Kotlin from its inputs (the earlier python reference model is retired to dev capture notes; the Kotlin port is pinned by synthetic-vector tests against it). 208 tests green, spec rev 31. A minimal public facade (`NacMint`) exposes the mint for consumers; the remaining gap to a live stamp is five wire-input mappings from the validation exchange, each named in the spec (§1.1 C56). No anisette server, no Unicorn, no Mac relay.

Not validated yet:

- No real message send or receive over the courier; renewal across sessions is untested.
- The crypto envelopes have round-trip tests but no known-answer vectors from a live device.
- A few wire details are capture-bound guesses, tracked in the spec's open-questions checklist.
- PQ3 is unsupported.

## Why another project?

Almost every route to iMessage is closed in some way. Open Madrid is permissively licensed, dependency-light, and fully readable.

| Project | License / catch |
|---|---|
| rustpush | SSPL |
| pypush | SSPL |
| imessagego | AGPL |
| BlueBubbles | Needs a Mac running 24/7 |
| OpenBubbles | Depends on closed-source open-absinthe |

Protocol facts live in the spec: [docs/imessage-protocol-spec.md](docs/imessage-protocol-spec.md).

## Contributing

This is a clean-room. Contributors never read the source of rustpush, pypush, imessagego, or their forks. Two roles, kept apart:

1. Readers study the existing projects. Their only output is the spec.
2. Writers work only from the spec, Apple's documentation, and recordings of their own device's traffic. Don't open other projects' source or paste their identifiers into commits or issues.

This keeps the code fully open and acceptable to F-Droid and other distribution channels.

## Apple material

No Apple-derived code or binary ships here, including the IMDAppleServices framework. The bundled identity in `registration/src/main/resources/imessage/fairplay/` is a synthetic placeholder, generated and self-signed, for tests only. Live activation requires Apple's real FairPlay identity, which each user stages themselves.

One deliberate exception in spirit, documented for auditability: the ClearADI and pear white-box lookup tables (the constants the ADI OTP cipher and the NAC mint need) are constant *data* reconstructed by analyzing a compiled ADI implementation, and they ship as generated Kotlin source (`ClearAdiTablesData.kt`, `PearTablesData.kt`) decoded at startup — no Apple code, binary, or resource file is committed. The extraction method and every derived fact are documented in the spec.

## Building

```bash
./gradlew build             # all modules + tests
./gradlew :engine:runProbe  # live drift check
```

## License

[Apache-2.0](LICENSE).

Support my work on [Ko-fi](https://ko-fi.com/fenleon) or [GitHub Sponsors](https://github.com/sponsors/fenleon).
