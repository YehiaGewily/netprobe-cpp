# Code Signing Policy

> **Status: Draft — NetProbe releases are currently unsigned.**
>
> This document describes how NetProbe binaries **will** be signed once
> code-signing is enabled. It is published now so that reviewers at the
> SignPath Foundation (or any user evaluating the project) can see the
> intended controls before the first signed release ships. Every use of
> "is signed" below should be read as "will be signed."
>
> When the first signed release ships this banner will be removed and the
> language will change to present tense in the same commit.

## Scope

The following Windows executables will be signed for every published
release:

- `NetProbe.exe` — the GUI application
- `netprobe-cli.exe` — the headless CLI

Signing is **not** planned for the release ZIP itself, `SHA256SUMS.txt`,
or the third-party licence file. Those integrity properties are covered
by the SHA-256 checksums the release job publishes.

macOS binaries are not covered by this document. Apple Developer ID
signing and notarization will be documented separately when the project
enrolls with the Apple Developer Program.

## Where signing happens

Signing will happen **only** in GitHub Actions, and **only** on tag
pushes matching `v*` on the `main` branch of this repository:

- <https://github.com/YehiaGewily/netprobe-cpp>

A tag push runs the standard build matrix, then the release job downloads
the Windows artifact, submits it to the signing service, and attaches the
signed artifact together with `SHA256SUMS.txt` to the GitHub Release.

**Signing will never happen on:**

- Pull requests (including PRs from maintainers). PRs run the full build
  and test matrix, but the release job is gated on
  `startsWith(github.ref, 'refs/tags/v')`.
- Feature branches or `main`-branch commits without a version tag.
- Local developer machines. Only the GitHub Actions runner will hold
  signing credentials; the maintainer's local environment will not.

## People and roles

NetProbe is a solo-maintained open-source project. All three roles below
map to the same GitHub account today:

- **Committer** — the person authoring changes.
  Currently: [YehiaGewily](https://github.com/YehiaGewily).
- **Reviewer** — the person merging changes to `main` and pushing
  version tags. Currently: [YehiaGewily](https://github.com/YehiaGewily).
- **Approver** — the person approving a signing request in the signing
  service (SignPath). Currently: [YehiaGewily](https://github.com/YehiaGewily).

Two-factor authentication is required on the GitHub account. If
additional maintainers are added later, this document will be updated
in the same commit that grants them access, so the record here always
reflects the live access list.

## Build integrity

Each signed artifact will be built from a specific Git commit reachable
from the signed tag. The build:

1. Checks out the exact tag from GitHub.
2. Compiles the source using the GitHub-hosted runner images (currently
   `windows-latest`). Third-party dependencies are pinned at Git tags
   via CMake `FetchContent`. Git tags are mutable in principle; the
   upstream tags NetProbe consumes (`mbedtls/v3.6.2`, `glfw/3.4`, etc.)
   have not moved historically. When the project needs stronger
   guarantees — for example ahead of an audit — these will be pinned
   to commit SHAs instead of tags.
3. Runs the full test suite (89 tests as of v1.2.1) and the sanitizer
   job that gates release publication.
4. Packages the ZIP via CPack. The layout is verified by a smoke test
   that extracts the ZIP and runs the CLI from it; the build fails if
   unexpected files appear.

The signed binary's exact commit can be recovered from the corresponding
GitHub Release page (`Source code` assets and the release notes, which
`gh release create --generate-notes` populates from the commit range
since the previous tag).

**Runner image drift.** The build uses `*-latest` runner images rather
than pinned images. This is a deliberate tradeoff: pinning gives
reproducibility but requires ongoing image-version maintenance, and
image drift has not been a source of shipping bugs for this project so
far. If SignPath or another signing authority requires pinned runners,
that pinning will land before the first signed release.

## Verifying a signed release

Windows (PowerShell):

```powershell
Get-AuthenticodeSignature .\NetProbe.exe | Format-List *
Get-AuthenticodeSignature .\netprobe-cli.exe | Format-List *
```

Once signing is live, the `Status` field should read `Valid` and the
`SignerCertificate` subject should identify the publishing organization.
If either binary reports `NotSigned`, `HashMismatch`, or a different
signer, do **not** run it — open an issue.

Every release ZIP also carries SHA-256 checksums published as
`SHA256SUMS.txt` on the same release page. Checksum verification works
for both signed and unsigned releases.

## Acknowledgments

This project intends to use the SignPath Foundation's free code-signing
programme for open-source projects. The specific acknowledgment text
required by SignPath's terms will be added to this document (and, if
appropriate, to the project's README) as part of the application
process.

## Reporting misuse

If you observe a NetProbe binary signed with the project's certificate
but distributed from outside the official GitHub Releases page, or you
have reason to believe the signing credentials have been misused, please
report it via GitHub's private security advisory form:

<https://github.com/YehiaGewily/netprobe-cpp/security/advisories/new>

See [SECURITY.md](SECURITY.md) for the full security-reporting policy.

## Change history

- **Unreleased** — Initial draft published in support of a SignPath
  Foundation application. Windows signing is not yet active; enabling it
  in CI is planned as a follow-up landing in a version bump.
