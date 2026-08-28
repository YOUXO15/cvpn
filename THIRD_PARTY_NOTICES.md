# Third-party notices

This client integrates the following components. GPL projects inspected during
research are not copied into this project.

- [SwiftyXrayKit](https://github.com/dima-u/SwiftyXrayKit), revision
  `3c5405521ae547de110f6ea65df00b1c05f6a0bc`, Apache License 2.0. Its source is
  vendored with a narrow Swift 6 sendability patch in `Vendor/SwiftyXrayKit`.
- [libXray](https://github.com/XTLS/libXray), release `v26.3.27-ios`, MIT License.
- [Xray-core](https://github.com/XTLS/Xray-core), version `v26.3.27`, Mozilla
  Public License 2.0.
- [tun2proxy](https://github.com/tun2proxy/tun2proxy), version `0.8.3`, MIT
  License. The local shim calls its public asynchronous API and deliberately
  avoids the generic process-exit wrapper inside the iOS extension.
- [v2fly/geoip](https://github.com/v2fly/geoip), release `202608050239`,
  Creative Commons Attribution-ShareAlike 4.0.
- [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community),
  release `20260827152101`, MIT License.

The release identifiers and checksums are pinned in the vendored `Package.swift`
and in `scripts/fetch-geo.sh`.
