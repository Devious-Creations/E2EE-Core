# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue for a suspected vulnerability.

Use GitHub's **private vulnerability reporting**: on this repository, go to the
**Security** tab → **Report a vulnerability**. We will acknowledge, discuss,
and coordinate disclosure there.

Non-sensitive feedback (docs, style, test ideas) is welcome as a normal issue
or PR.

## Scope

Everything in this repository is in scope — see the README's
[threat model](./README.md#threat-model) for what the system claims, and
[what we'd especially love reviewed](./README.md#what-wed-especially-love-reviewed)
for the questions we most want answered.

Platform code that *consumes* this package (device keychain, transports,
servers) is not published here; the threat model treats the server and
transport as untrusted by design, so the claims above must hold even when
those components are adversarial. A finding of the form "a conforming consumer
can misuse this API into an insecure state" is absolutely in scope.

## Supported versions

`main` and the latest tagged release. The consuming app pins a specific commit
and updates deliberately, so a fix lands here first and is then rolled into
the app.
