# Third-party notices

KindlyVPN is a GPL-3.0 derivative and retains the repository's GPL license.

- [v2rayNG 2.2.6](https://github.com/2dust/v2rayNG/tree/2.2.6), GPL-3.0, supplies the Android VPN,
  subscription, Xray configuration, and UI base.
- [AndroidLibXrayLite v26.7.5](https://github.com/2dust/AndroidLibXrayLite/releases/tag/v26.7.5)
  supplies the Xray Android library.
- [Moroka8/vk-turn-proxy v1.10.1](https://github.com/Moroka8/vk-turn-proxy/tree/v1.10.1),
  GPL-3.0, supplies the TURN transport helper, SRTP-shaped WRAP, and VLESS bonding. KindlyVPN
  pins commit `e87b50a413aa401436d73216e586d4dc47223c5a`, applies the Android integration patch in
  `scripts/patches/`, and builds with 16 KiB page alignment. The reproducible build is in
  `scripts/prepare-native-dependencies.sh`.
- [icyfalc0n/maxcalls](https://github.com/icyfalc0n/maxcalls), GPL-3.0, documents the MAX
  WebSocket and calls authentication flow used by the experimental MAX credential provider.
- [somewhat-industries/swinter-android](https://github.com/somewhat-industries/swinter-android),
  Unlicense, provided an independent reference for MAX SMS and 2FA response handling. KindlyVPN
  does not use Swinter binaries and retains normal platform TLS certificate verification.
- [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel), MIT, supplies the optional TUN
  forwarding library inherited from v2rayNG.

The Gradle license-report plugin generates notices for Maven dependencies. Preserve this notice,
the root `LICENSE`, source code, and build scripts whenever distributing an APK.
