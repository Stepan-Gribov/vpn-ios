# TnDtun publication rules

- Use the personal `Stepan-Gribov` account for iOS commits, tags and releases.
  Publish public source changes to `Stepan-Gribov/vpn-ios`.
- Check the push URL, outgoing commit history and diff before pushing.
  Base public changes on the current public branch. Keep private history,
  panel and subscription data, signing material and compiled binaries out of it.
- Use the app owner's Apple signing team for signed builds. Store authorized
  signed assets only in private `Stepan-Gribov/vpn-builds` after checking its
  owner and visibility. Verify downloaded release assets by SHA-256.
- Keep any KindlyVPN remotes fetch-only. Upload to App Store Connect only on
  explicit request.
