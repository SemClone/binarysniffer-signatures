# Security Policy

This repository distributes signed signature bundles for
[binarysniffer](https://github.com/SemClone/binarysniffer). Because these
signatures are downloaded and imported by the tool, their integrity and
authenticity matter.

## Reporting a vulnerability

Please report security issues privately to **security@semcl.one**. You will
receive a response within 48 hours.

Report here if you find:

- A **malicious, incorrect, or suspicious signature** in a published bundle
  (for example, a signature that would cause dangerous misclassification).
- A problem with a bundle's **Ed25519 signature or SHA-256 manifest**, or any
  way to make the client accept an unverified or tampered bundle.
- Suspected **compromise or misuse of the signing key** or the publishing
  workflow.

Please include, where applicable: the affected release tag and asset, the
signature or file in question, and steps to reproduce.

## How bundles are protected

- Every bundle is signed with an Ed25519 key; the tool verifies the signature
  against a trusted public key before installing.
- Every file inside a bundle is verified against a per-file SHA-256 manifest.
- The signing private key is held only as a repository secret and is never
  committed. Key rotation is supported by trusting more than one public key
  during the transition.

Do not open public issues for security reports. For vulnerabilities in the tool
itself, use the [binarysniffer security policy](https://github.com/SemClone/binarysniffer/blob/main/SECURITY.md).
