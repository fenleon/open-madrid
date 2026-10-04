# Open Madrid

An open implementation of Apple's madrid protocol (iMessage) in Kotlin. Covers the property-list codecs, the APNs "courier" push client, the IDS identity service, the encryption envelope, and the registration/activation chain.

Unlike [open-absinthe](https://github.com/JJTech0130/open-absinthe), which is a mock placeholder with no real code, everything here is readable and Apache-2.0 licensed.

## Status

Validated:

- The parsers handle real Apple bytes. The actual 405-entry IDS bag and 65-entry APNs bag, captured from a registered device, are committed as test fixtures and decoded with exact-value assertions.
- The registration chain ran live against Apple (2026-10-02→04, spec rev 26): Albert activation, the packed APNs courier, the full GSA sign-in (SRP, trusted-device 2FA, PET delivery, postdata), then IDS authenticate and register — both green, `mailto:` handle active. The earlier 409 refusals turned out to be Apple's validation-stamp replay guard (one mint = one device record), documented in the spec.
- Two live unauthenticated probes against Apple succeeded: both bag endpoints return plists this stack parses, and certificate pinning validates Apple's real TLS chains. A drift check ships with the repo (`:engine:runProbe`).
- The courier's auth model is settled: the packed path needs no client certificate; the legacy path answers the handshake with a TLS 1.3 post-handshake `certificate_required` alert.

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

## Building

```bash
./gradlew build             # all modules + tests
./gradlew :engine:runProbe  # live drift check
```

## License

[Apache-2.0](LICENSE).

Support my work on [Ko-fi](https://ko-fi.com/fenleon) or [GitHub Sponsors](https://github.com/sponsors/fenleon).
