# Generic iOS Packet Tunnel Client

Public build-only source repository for a native iOS tunnel client. It
contains the SwiftUI application, Packet Tunnel extension, local Xray bridge,
security tests, and the workflow that produces a re-sign-ready IPA.

The server, deployment configuration, subscription credentials, signing
certificates, provisioning profiles, and private repository history are not
included.

## Security

- Subscription imports require HTTPS, Apple system trust, and an exact SPKI pin.
- Redirects are restricted to the same pinned host.
- Imported profiles are stored in the iOS Keychain with `ThisDeviceOnly`
  protection.
- Profile contents and subscription addresses are excluded from diagnostics.
- The Packet Tunnel configuration is kept transient and removed after startup.

The real host allowlist and certificate pins are supplied to CI through an
encrypted repository secret and are not committed. For local development, copy
`Resources/App/SecurityPolicy.example.plist` to `SecurityPolicy.plist` and use
non-production test values.

## Build

The `iOS client IPA` workflow runs security/parser tests and a real Darwin TUN
round-trip probe on a GitHub-hosted Mac before creating the unsigned artifact.
The Packet Tunnel runs Xray as a loopback SOCKS server and builds a small
managed wrapper around MIT-licensed tun2proxy for TUN-to-SOCKS transport.
The result must be re-signed with an Apple certificate and provisioning profiles
that authorize `packet-tunnel-provider` for both the app and its embedded
extension.

Local requirements: macOS, Xcode 16+, XcodeGen, and Rust 1.85+.

```sh
sh scripts/fetch-geo.sh
sh scripts/build-tun2proxy-shim.sh
xcodegen generate
sh scripts/build-unsigned-ipa.sh
```

The generated artifact is `output/TunnelClient-resign-ready.ipa`.
