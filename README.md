# binarysniffer-signatures

Distribution point for [binarysniffer](https://github.com/SemClone/binarysniffer)
signature bundles. This repository is public so the tool can fetch signature
updates while the tool source stays private.

Each GitHub Release carries a signed bundle:

- `signatures-<date>-<run>.zip` — the signature set plus a manifest of per-file
  SHA-256 hashes.
- `signatures-<date>-<run>.zip.sig` — an Ed25519 detached signature over the zip.

`binarysniffer update` downloads the latest bundle, verifies the signature
against the trusted public key baked into the tool, verifies every file against
the manifest, and installs it. Do not trust a bundle that fails verification.

The `Publish Signatures` workflow builds and signs the bundle on a schedule and
on demand.
