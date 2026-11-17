# Ledger 8 transient-crypto compatibility source

This directory preserves `midnight-transient-crypto` 2.2.0 from the signed
`transient-crypto-2.2.0` tag (`a0cb6de6995afc68a92eb984d01ff43c2788f0a2`)
for Ledger 9 legacy-state translation.

The Rust sources are unchanged except that `proofs.rs` reuses the
byte-identical verifier-parameter blob already present in the sibling current
package. Its path dependencies intentionally resolve to the current in-tree
base, serialization, and corrected storage-core packages, matching the
compatible versions selected by the published crate while keeping `sysinfo`
out of normal mobile builds.

This compatibility package is not published and is excluded from default
workspace members. Remove it only when Ledger 9 no longer reads the legacy
transient-crypto format.
