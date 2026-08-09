# binarysniffer-signatures

Signed, versioned signature bundles for
[binarysniffer](https://github.com/SemClone/binarysniffer), the open-source
component-detection tool. This is the signature database that `binarysniffer
analyze` matches against.

## What this repository is

binarysniffer identifies open-source components in binaries and archives by
matching them against a database of signatures. That database is published here
as a single signed archive attached to a GitHub Release. Each release contains:

- `signatures.zip`: the signature set plus a `manifest.json` of per-file
  SHA-256 hashes.
- `signatures.zip.sig`: an Ed25519 detached signature over the archive.

## Why it is a separate repository

Signatures change more often than the tool does. Keeping them here, with their
own release cadence, lets you pick up new and improved detections by running one
command, without upgrading or reinstalling binarysniffer.

Publishing the bundles in the open and signing each one means anyone can
download a bundle, see exactly which signatures it contains, and verify that it
was produced by the maintainers and has not been modified.

## How updates work

`binarysniffer update`:

1. Finds the latest release here that has a signature bundle.
2. Downloads `signatures.zip` and `signatures.zip.sig`.
3. Verifies the Ed25519 signature against the trusted public key shipped in the
   tool.
4. Unpacks the archive and checks every file against the manifest's SHA-256.
5. Installs the verified signatures.

A bundle that fails signature or hash verification is rejected and never
installed.

## Using it

```bash
# The update extra provides signature verification
pip install 'binarysniffer[update]'

# Pull and verify the latest signatures
binarysniffer update
```

The trust model and verification details are in the tool's
[Signature Updates guide](https://github.com/SemClone/binarysniffer/blob/main/docs/SIGNATURE_UPDATES.md).

### Verifying a bundle manually

You can verify a downloaded bundle yourself with the trusted public key (also in
the tool at `binarysniffer/signatures/trusted_keys.py`):

```python
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(TRUSTED_PUBLIC_KEY_B64))
pub.verify(base64.b64decode(open("signatures.zip.sig").read().strip()),
           open("signatures.zip", "rb").read())  # raises if invalid
```

## Contributing signatures

Signatures are authored in the main
[binarysniffer](https://github.com/SemClone/binarysniffer) repository and
published here automatically. To propose a new or improved signature, see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Security

To report a malicious, incorrect, or suspicious signature, or a problem with a
bundle's signature or integrity, see [SECURITY.md](SECURITY.md).

## License

The signature data in this repository is licensed under
[Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)](LICENSE):
you may share and adapt it, with attribution, for non-commercial purposes. For
commercial use, contact the maintainers to discuss licensing.

The binarysniffer tool itself is licensed separately under Apache-2.0.
