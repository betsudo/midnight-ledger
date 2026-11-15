# Branch names for release-line upgrades

Use `<role>/<release-line>/<artifact>-<version-or-topic>`, all lowercase with hyphens. The release line names the consumer compatibility target (`ledger9` here). Put the exact upstream tag or recorded published-crate source SHA in the branch description and PR body. Avoid dates and ambiguous names such as `patched` or `latest` in new branch names.

| Role | Purpose | Ledger9 example |
| --- | --- | --- |
| `sync` | Immutable pointer to the verified upstream tag or published-crate source. No optimization commits. | `sync/ledger9/ledger-9.1.0.1` |
| `integration` | Fork release line, initialized from `sync` and advanced only by reviewed merges. PRs target this branch. | `integration/ledger9/ledger-9.1.0.1` |
| `opt` | One reviewable optimization or compatibility change. | `opt/ledger9/proofs-native-memory` |
| `fix` | One regression fix against the integration line. | `fix/ledger9/v3-cancellation` |
| `docs` | Documentation with no behavior change. | `docs/ledger9/storage-policy` |

Agent-owned scratch and proposal branches may prefix the role with `codex/`, for example `codex/opt/ledger9/proofs-native-memory`. The prefix identifies ownership; the remaining segments retain the same meaning. Prefer a short-lived PR branch over rewriting an occupied worktree or a published integration head.

For this graph, use `sync/ledger9/proofs-0.8.2` and `integration/ledger9/proofs-0.8.2` in `midnight-zk`; `sync/ledger9/zkir-3.2.1` and `integration/ledger9/zkir-3.2.1` in `midnight-zkir`; and the Ledger branches shown above in `midnight-ledger`. ZKIR 3.2.1 is anchored to the published crate's recorded source commit because its Git tag does not identify the packaged 3.2.1 source. The PR description must explain that exception.

Create a new release line for Ledger10 or another package upgrade. Do not move a `sync` branch after publication. If upstream corrects a tag or releases a new package, create a new versioned `sync` and `integration` pair and compare the official release delta before replaying fork changes.
