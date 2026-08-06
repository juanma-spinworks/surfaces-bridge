# Security policy

## Supported versions

No npm release is supported until it is published from this repository and
explicitly allowlisted by the SpinWorks Surfaces service.

After publication, only the latest allowlisted version is supported.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability or include credentials,
pairing codes, tokens, private keys, or customer data in a report.

Use GitHub's private vulnerability reporting for this repository:

1. Open the **Security** tab.
2. Select **Advisories**.
3. Select **Report a vulnerability**.

SpinWorks will acknowledge a complete report as soon as practical and coordinate
disclosure and remediation with the reporter.

## Credential model

The bridge stores its Ed25519 private key and Surfaces session credentials in
macOS Keychain. Its metadata file contains identifiers and endpoint information,
not the private key or bearer credentials. A compromise report should state
whether the host, Keychain session, or Surfaces account may also be compromised.
