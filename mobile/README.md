# Digilompakko — native mobile wallets

Native holder apps for the Digilompakko EUDI wallet demo: **iOS (Swift / SwiftUI)** and
**Android (Kotlin / Jetpack Compose)**. They drive the same OpenID4VCI / OpenID4VP flows as the
TypeScript `apps/wallet`, but with **hardware-backed keys** — the whole point of going native.

```
mobile/
├── ios/        Swift + SwiftUI app (Secure Enclave holder key)
└── android/    Kotlin + Jetpack Compose app (Android Keystore / StrongBox holder key)
```

## What works today

- **Holder key in secure hardware** — iOS **Secure Enclave**, Android **StrongBox** (TEE keystore
  fallback). The private key is non-exportable; the app only asks the hardware to sign (ES256/P-256).
  This is the on-device **WSCD** that the TS demo abstracts as `SoftwareKeyStore`.
- **OpenID4VCI issuance** — pre-authorized code flow: fetch offer → token → sign a Proof-of-Possession
  in hardware → receive and store an **SD-JWT VC**.
- **OpenID4VP presentation** — fetch the verifier's **signed request object (JAR)**, verify the RP
  signature against its published JWKS, then present **only the attributes the user selects** (real
  selective disclosure) with a hardware-signed **Key Binding JWT**.
- **Polished UI** — wallet home with credential cards, a key-security banner, and a consent screen
  with per-attribute disclosure toggles.

## Not yet (next steps)

- **mdoc / mDL (`mso_mdoc`)** — the protocol core exists in `packages/core` and the TS apps; the
  native apps currently implement **SD-JWT VC** only. Full CBOR/COSE in Swift and Kotlin is the next
  milestone (the UI and key/keystore layers are already format-agnostic enough to extend).
- Authorization Code + PAR + PKCE issuance, mdoc revocation display, proximity (BLE/NFC).

## Prerequisites

Run the demo services from the repo root so the apps have an issuer + verifier to talk to:

```bash
cd ..            # repo root
npm install && npm start   # issuer :4001, verifier :4002, (TS wallet :4000)
```

## iOS

Requires Xcode 15+ and [XcodeGen](https://github.com/yonyz/XcodeGen) (`brew install xcodegen`).

```bash
cd mobile/ios
xcodegen generate          # creates Digilompakko.xcodeproj from project.yml
open Digilompakko.xcodeproj
```

In Xcode: select the **Digilompakko** target → Signing & Capabilities → pick your Team, then Run.

- **Simulator**: reaches the Mac's `localhost` directly — works out of the box. Note the Secure
  Enclave is **not** available on the Simulator, so it transparently uses a software key (the banner
  shows which). 
- **Real device**: edit `Config.issuerURL` / `Config.verifierURL` in `Wallet.swift` to your Mac's
  LAN IP (e.g. `http://192.168.1.10:4001`). The holder key is then truly in the Secure Enclave.

## Android

Open `mobile/android` in **Android Studio** (Giraffe+); let it sync Gradle. (CLI: run
`gradle wrapper` once if `./gradlew` is missing, or just use Android Studio's bundled Gradle.)

- **Emulator**: reaches the host machine via `10.0.2.2` (already the default in `Config.kt`). Run.
- **Real device**: set `Config.issuerURL` / `Config.verifierURL` in `Wallet.kt` to your machine's
  LAN IP. **StrongBox** is used on supported devices; otherwise the TEE-backed keystore (the banner
  shows which).

## Security & demo notes

- The cleartext/ATS exceptions (iOS `Info.plist`, Android `network_security_config.xml`) exist
  **only** so the apps can reach the local HTTP demo services. Remove them for any real deployment.
- These are reference clients, not certified wallets — see `../docs/PRODUCTIONIZATION.md` for the
  full gap (hardware attestation, real PID/eID, trusted lists, certification, …).

## How this maps to the TS core

The native apps re-implement the protocol logic (`SdJwt`, `Jose`, `SecureKeyStore`, `Wallet`) that
lives in `packages/core` for the TS apps — per the **native Swift + Kotlin** architecture choice,
which trades code reuse for first-class platform crypto and hardware key storage.
