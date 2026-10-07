# Security

## Reporting a problem

Report a vulnerability in this Action or the service to <https://vaultbytes.com/contact.html>, topic "Security". Please do not open a public issue for it. We aim to acknowledge a report within three working days.

## What this Action handles

It holds one secret, your VaultBytes Verify token. It reads the workflow's own metadata (repository, commit, ref), sends a job request to the VaultBytes Verify service, polls until the job finishes, and writes the verdict to the job summary, the step outputs and a `result.json` artifact. It does not read or upload your source code. The service clones the commit itself.

## How to use it safely

1. **Pin to a full commit SHA, not a tag.** A tag name such as `v0` or `v0.2` can be moved; a commit SHA cannot. Use the SHA shown on the release page and keep the version in a comment:
   `uses: BAder82t/verify-action@<40-character SHA> # v0.2`
   Let Dependabot (`package-ecosystem: github-actions`) propose updates, and review each one.
2. **Give the workflow the smallest token.** Add `permissions: contents: read` at the top of the workflow. The Action needs no other GitHub permission.
3. **Run it on `push` and `pull_request` only.** GitHub withholds secrets from pull requests that come from forks, so the check does not run for them and no fork author can read the token. Do not use `pull_request_target` or `workflow_run` with this secret. The Action refuses to start on those two events, before it reads the token.
4. **Store the token as a repository or environment secret**, never as a literal in the file or a workflow variable. Rotate it if it may have been exposed.
5. **Check a release before you trust it** (see below).

## Outbound network behaviour

The Action contacts exactly one host: the service URL. That is the `api-url` input, else the `VBV_API_URL` variable, else the URL built into the release. It must be `https` (plain `http` is accepted only for `127.0.0.1` and `localhost`, for testing). It makes two kinds of request:

| Request | Sent | Purpose |
|---|---|---|
| `POST /v1/jobs` | repository clone URL, ref, commit SHA, and the optional `library`, `suite`, `job-timeout-seconds` and `worst-case` values | start a job |
| `GET /v1/jobs/{id}` | nothing beyond the header | poll for the verdict |

Every request carries `Authorization: Bearer <token>` and nothing else of yours. Redirects are refused, so the token cannot be forwarded to another host. The Action has no runtime dependencies, makes no other network calls and does not download code at run time. It also contacts no GitHub API itself. The upload step uses the GitHub artifact service through the pinned `actions/upload-artifact`. A signed report link, when shown, must be on the service's own origin or it is dropped.

The token is passed to the step as an environment variable, masked in the log with `::add-mask::`, and removed from any text the Action prints (including text returned by the server).

## Verifying a release

Releases are built by the `release` workflow from an annotated tag. Each release carries a source archive, its SHA-256 checksum and a Sigstore build-provenance attestation. To check one:

```
gh release download v0.2 --repo BAder82t/verify-action
sha256sum -c verify-action-v0.2.tar.gz.sha256
gh attestation verify verify-action-v0.2.tar.gz --repo BAder82t/verify-action
```

The commit that the release points at is printed in the release notes. That is the value to pin.

## For maintainers

- Release tags are annotated and signed: `git tag -s v0.2 -m "v0.2"` (SSH signing works: `git config gpg.format ssh`), then `git tag -v v0.2`. The release workflow refuses a lightweight tag.
- In the repository settings, turn on **immutable releases** and a tag ruleset on `v*` that blocks deletion and updates, so a published tag and its assets cannot be moved. Moving the major tag (`v0`) is no longer done: consumers pin SHAs.
- Every workflow here sets `permissions: contents: read` at the top, uses no `pull_request_target`, and pins each third-party action to a commit SHA. `test/supply-chain.test.mjs` fails if that stops being true.
