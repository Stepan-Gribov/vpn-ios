# TnDtun publication rules

- Use the personal `Stepan-Gribov` account for iOS commits and pushes.
  Publish public source changes to `Stepan-Gribov/vpn-ios`.
- Check the push URL, outgoing commit history and diff before pushing.
  Base public changes on the current public branch. Keep private history,
  panel and subscription data, signing material and compiled binaries out of it.
- Keep any KindlyVPN remotes fetch-only. GitHub holds iOS source only, including
  the `vpn-builds:source/ios` snapshot. Keep IPA files, archives, release tags,
  releases and build download links out of GitHub for iOS.
- Deliver iOS builds through the existing Apple channel only on explicit request.
  Use the app owner's Apple signing team and bundle IDs.
