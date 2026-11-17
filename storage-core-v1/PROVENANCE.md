# Legacy storage-core compatibility source

This directory contains the source published as
`midnight-storage-core 1.2.3` on crates.io (checksum
`aa4923fc43b6202934516e5b897983a9390d78076ca7059a46c2d17989dbe891`).
It is retained for the `midnight-transient-crypto 2.2.0` compatibility path
used by Ledger 9 state translation.

The source files are unchanged. The manifest-only compatibility changes are:

- rename the package to `midnight-storage-core-legacy` so Cargo can retain it
  alongside the current in-tree package with the same upstream version;
- resolve base crypto, serialization, and macros from this Ledger checkout;
- mark the compatibility package as non-publishable; and
- remove the unconditional, unused `sysinfo` dependency. No library source in
  the published package references `sysinfo`; removing it avoids unsupported
  host-inspection APIs on iOS and Android without changing storage behavior.

The package is excluded from the default workspace and is reachable only
through the explicit `transient-crypto-v2` path dependency.
