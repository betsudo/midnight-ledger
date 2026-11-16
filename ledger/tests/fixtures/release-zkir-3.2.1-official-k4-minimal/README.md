# ZKIR 3.2.1 with the Ledger9 official k=4 parameter

This small V3 fixture was produced and verified by the **published**
`midnight-zkir` 3.2.1 source at `8825fb5a` with its locked registry
dependencies: `midnight-proofs` 0.8.2, `midnight-zk-stdlib` 2.4.0, and
`midnight-transient-crypto` 3.0.0. Unlike the adjacent generated-parameter
fixture, its SRS is the official `bls_midnight_2p4` object listed in the
Ledger 9.1.0.1 `flake.nix` `public-params` manifest. The downloaded object
was 3,460 bytes with SHA-256
`232f401fad10c7ddf8828d2aa4c85c6506c5da09795998cecaeb9f75fc8f6ada`,
matching the manifest's Nix hash
`sha256-Iy9AH60Qx934go0qpMhcZQbF2gl5WZjOyuufdfyPato=`.

The published-source producer generated the key and proof locally against
that official SRS. **This is not a network-distributed production proving
key.** The `release_source_v3_key_with_official_k4_params_remains_usable`
test verifies the baseline proof with the optimized Ledger9 verifier,
round-trips the tagged key, and proves and verifies with heap and, when
`native-memory` is enabled, mapped-key/forced-coset-spill policies. The
separate released key distribution and high-k memory gates remain open.

To reproduce, use a detached checkout of published ZKIR source `8825fb5a`,
copy the adjacent `../release-zkir-3.2.1-v3-minimal/generate.rs` to
`zkir/tests/release_fixture_local.rs`, and run the command below. Keep the
producer lockfile on registry packages.

```sh
MIDNIGHT_RELEASE_V3_OUT=/path/to/temporary-output \
MIDNIGHT_RELEASE_V3_PARAM=/path/to/verified/bls_midnight_2p4 \
  cargo test -p midnight-zkir --test release_fixture_local --locked -- \
  --exact produce_release_source_v3_fixture --nocapture
```

The producer's verified SRS bytes, IR, preimage, and key encodings are
reproducible. Proof bytes may differ on regeneration; compare proof
verification rather than asserting byte identity.

| File under `minimal/` | SHA-256 |
|---|---|
| `zkir/minimal.zkir` | `789372be8426c8a60651d79920a8d90e062f484ed40a562da1f36bf6206eb391` |
| `params.bin` | `232f401fad10c7ddf8828d2aa4c85c6506c5da09795998cecaeb9f75fc8f6ada` |
| `keys/minimal.prover` | `7bdd1ab2bfa1c7419c5805555853834e7ba213d672a4b252aba5e677edd1ff34` |
| `keys/minimal.verifier` | `8b521cc90315e8272ee5128c9fdf6ffa6822c59efbda99f91474e5da3a6ec102` |
| `preimage.bin` | `8184e75fe928208f4469789caf47480a4fb176dd97b04ea9ba058e569f927183` |
| `proof.bin` | `63f71d1386b7631d8fdf31698b68c568501dd3d6eabd0324280ad7421bdcd130` |
