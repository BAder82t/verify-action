# VaultBytes Verify — GitHub Action

Checks that an FHE library computes the right answer, on every push.

The service generates its own test programs, runs them through your library in an isolated sandbox with no
network, checks every operation against an independently computed high-precision reference, and reports the
operation that broke with a small program that reproduces it. You write no tests and no configuration.

It has found and publicly reported real bugs in
[Lattigo v6.2.0](https://github.com/tuneinsight/lattigo/issues/581) and
[OpenFHE v1.5.1](https://github.com/openfheorg/openfhe-development/issues/1339), both of which return wrong
answers with no error raised.

## Status: private pilot

This Action is published so the workflow below resolves, but the service is in private pilot. You need a token,
and tokens are issued to pilot users. Ask for one at <https://vaultbytes.com/verify>.

## Use

Add your token as the repository secret `VBV_TOKEN`, then commit
`.github/workflows/vaultbytes-verify.yml`. Pin the Action to the full commit SHA of a release, and give the
workflow a read-only token:

```yaml
on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: BAder82t/verify-action@<40-character commit SHA of the release> # v0.2
        with:
          token: ${{ secrets.VBV_TOKEN }}
```

A tag such as `v0.2` can be moved, a commit SHA cannot. The release page shows the SHA to use.

Everything else is detected: the repository and commit come from the push, and the library and its version are
detected from your tree. The test programs, the parameters and the tolerance are chosen by the service and fixed
per version, so a run cannot be tuned into passing.

## Inputs

See [`action.yml`](action.yml). `token` is the only required one. `library`, `suite`, `fail-on`, `api-url`,
`timeout-seconds`, `poll-interval-seconds` and `job-timeout-seconds` all have defaults.

## Security

The Action holds your service token and runs in your CI, so how it is pinned, what it may do and what it talks to
are all documented in [`SECURITY.md`](SECURITY.md): pinning to a commit SHA, the minimal `contents: read`
permission, why it refuses the `pull_request_target` and `workflow_run` events, the one host it contacts and exactly
what it sends, and how to verify a release's checksum and signed provenance.

## What a pass means, and what it does not

A pass says the outputs matched an independent reference within a tolerance fixed by the checker, on the programs
that ran. It does not say a result was computed homomorphically rather than in the clear; that is a separate,
ciphertext-level guarantee. A run reports the conformance level it actually checked at, and the level is chosen by
the service, never declared by the code under test.

## Runner time

Today this Action waits for the job, which takes about 45 minutes of runner time. That is free on public
repositories and billed per minute on private ones. A future version submits and exits, with the verdict posted
back as a check on the commit.

---

© 2026 VaultBytes Innovations Ltd. Contact <https://vaultbytes.com> for licence terms.
