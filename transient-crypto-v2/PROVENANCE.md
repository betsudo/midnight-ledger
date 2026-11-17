# Ledger 8 transient-crypto compatibility source

This directory preserves `midnight-transient-crypto` 2.2.0 from the signed
`transient-crypto-2.2.0` tag (`a0cb6de6995afc68a92eb984d01ff43c2788f0a2`)
for Ledger 9 legacy-state translation.

The Rust sources are unchanged except that `proofs.rs` reuses the
byte-identical verifier-parameter blob already present in the sibling current
package. Its base, derive, and serialization dependencies resolve to the
compatible versions in this checkout. Its storage dependency resolves to the
separately preserved `storage-core-v1` source so legacy gas and state behavior
remain identical while the unused `sysinfo` dependency stays out of mobile
builds.

This compatibility package is not published and is excluded from default
workspace members. Remove it only when Ledger 9 no longer reads the legacy
transient-crypto format.
