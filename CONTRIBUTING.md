# Contributing

Thanks for helping improve binarysniffer's detection coverage.

## Where signatures live

Signatures are authored and reviewed in the main
[binarysniffer](https://github.com/SemClone/binarysniffer) repository. This
repository holds the **published, signed output** — the bundles attached to
releases — so it is not the place to edit signatures directly.

## Proposing a new or improved signature

Open a pull request (or issue) in the
[binarysniffer](https://github.com/SemClone/binarysniffer) repository:

1. Extract candidate signatures from a binary containing the target component
   (the tool can help: `binarysniffer signatures create ...`).
2. Add or update the component's JSON under `binarysniffer/signatures/data/`.
3. Follow the guidance in that repo's
   [CONTRIBUTING guide](https://github.com/SemClone/binarysniffer/blob/main/CONTRIBUTING.md)
   and [Creating Signatures](https://github.com/SemClone/binarysniffer/blob/main/docs/CREATING_SIGNATURES.md).

Aim for signatures that are specific to the component: overly generic strings
cause false positives against unrelated binaries.

## How changes reach this repository

Once merged in the tool repository, updated signatures are built into a bundle,
signed, and published here as a release. Contributions are accepted in the tool
repository, not by editing the published bundles.

## License of contributions

By contributing signature data you agree that it is published under this
repository's data license, **CC BY-NC 4.0** (see [LICENSE](LICENSE)). Only
contribute data you have the right to license this way.

## Code of Conduct

Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).
