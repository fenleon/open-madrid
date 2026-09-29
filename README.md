<p align="center">
  <a href="https://ko-fi.com/fenleon">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="art/coffee-hand-filled-alpha-white-steam.png">
      <img src="art/coffee-hand-filled-alpha-white.png" alt="Coffee hand" height="50" style="vertical-align: middle;">
    </picture>
  </a>
  <a href="https://ko-fi.com/fenleon">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="art/buy-me-a-coffee-alpha-white.png">
    <img src="art/buy-me-a-coffee-alpha-black.png" alt="Buy me a coffee" height="40" style="vertical-align: middle;">
  </picture>
  </a>
  <a href="https://ko-fi.com/fenleon">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="art/ok-hand-filled-alpha-white.png">
      <img src="art/ok-hand-filled-alpha-white.png" alt="OK hand" height="50" style="vertical-align: middle;">
    </picture>
  </a>
</p>
<p align="center">
  <a href="https://github.com/sponsors/fenleon"><strong>GitHub Sponsors</strong></a> ·
  <a href="https://ko-fi.com/fenleon"><strong>Ko-fi</strong></a>
</p>

# Open Madrid

**An open implementation of Apple's madrid protocol (iMessage).**

This repository is a clean-room, plain-old-open-source implementation of the iMessage protocol in Kotlin: the binary and XML property-list codecs, the APNs "courier" push client, the IDS identity service, the encryption envelope, and the full registration/activation chain.

Unlike [open-absinthe](https://github.com/JJTech0130/open-absinthe), whose public repository contains a
mock placeholder and no actual functionality, everything here is readable, and licensed.

## Why another project?

Almost every existing route to iMessage is closed in some way:

| Project | What it is | The catch |
|---|---|---|
| rustpush | The maintained engine (Rust) | SSPL license |
| pypush | The original Python PoC | SSPL license |
| imessagego | Go implementation | AGPL (the only ordinary open-source license in the space) |
| BlueBubbles | A working client | Needs a Mac running 24/7 to relay and decrypt |
| open-absinthe | The validation-data layer | Closed source |
| OpenBubbles hosted | A hosted service | Someone else's server sees your messages |

**Open Madrid's aim:** a permissively licensed (Apache-2.0), dependency-light, fully readable implementation of the protocol. Facts about the protocol live in a spec ([docs/imessage-protocol-spec.md](docs/imessage-protocol-spec.md)); every fact cites its source. Code is written from the spec, never from the other projects.

## What is validated

- **The parsers handle real Apple bytes.** The actual 405-entry IDS bag and 65-entry APNs bag,
  captured from a registered device, are committed as test fixtures and decoded with exact-value
  assertions.
- **Two live, unauthenticated probes against Apple succeeded:** both bag endpoints return valid
  plists this stack parses, and the certificate pinning validates Apple's real TLS chains. A
  recurring drift check ships with the repo (`:engine:runProbe`).
- **The courier's auth model is settled:** the TLS handshake succeeds, then the server demands
  the Albert client certificate (a TLS 1.3 post-handshake `certificate_required` alert).
- **The registration chain runs end-to-end against scripted Apple responses** (a full dry-run
  test).
- **The protocol around it is proven live** by this project's private sibling implementation:
  a working device-identity chain (Apple's validation endpoint, key establishment, the 645-byte
  validation blob), SRP login with Apple's GSA endpoints, and the decrypted response parsing —
  on real accounts. Those findings are folded into the spec here.

## What is not validated (yet)

- **Nothing has registered a real device or sent a real message.** First live activation is the
  next milestone.
- The crypto envelopes have round-trip tests but no known-answer vectors captured from a live
  device.
- A few wire details remain capture-bound guesses, tracked in the spec's open-questions checklist.
- **PQ3** (Apple's newer post-quantum encryption) is unsupported (today).

## Keeping the license clean (read this before contributing)

This is a **clean-room**: contributors never read the source of rustpush, pypush, imessagego, or
their forks. Two roles, kept strictly apart:

1. **Readers** study the existing projects. Their only output is the **spec**, a plain-language
   protocol notes with cited sources.
2. **Writers** work only from the spec, Apple's own documentation, and recordings of their own
   device's traffic. Don't open the other projects' source, don't read their diffs or issues when
   debugging, and don't paste their identifiers into commits or issues.

Why: it keeps this code fully open, acceptable to F-Droid and other distribution channels, and safe to embed anywhere.

## The Apple-material rule

No Apple-derived code or binary ships in this repository. This includes the IMDAppleServices framework, not Apple's FairPlay identity. The bundled identity under
`registration/src/main/resources/imessage/fairplay/` is a **synthetic placeholder** (generated, self-signed, for tests only). Live activation requires Apple's real FairPlay identity and registration framework, which each user stages themselves.

## Building

Standalone — no sibling checkouts required:

```bash
./gradlew build          # all modules + the full test suite
./gradlew :engine:runProbe   # the live drift check (unauthenticated bag/cert probes)
```

## License

[Apache-2.0](LICENSE).
