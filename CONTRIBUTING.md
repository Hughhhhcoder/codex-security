# Contributing

Thanks for helping improve Codex Security. We welcome bug reports, feature
requests, documentation corrections, and feedback from open-source
maintainers.

## How this repository works

Codex Security is developed in OpenAI's canonical repository and published
here through a one-way mirror. We can't import pull requests from this
repository into the canonical source.

Search [existing issues](https://github.com/openai/codex-security/issues)
before opening a new one. Maintainers can carry accepted changes into the
canonical source or invite a focused pull request for this public repository.

## Support for open-source projects

If you maintain an open-source project,
[open an issue](https://github.com/openai/codex-security/issues/new) with the
repository, your role, and what you need. Support is best effort. Scan only
repositories you trust and either own or have permission to assess.

## Report a bug

Include your CLI or SDK version, operating system, reproduction steps, and
the expected and observed behavior. Remove credentials, private code,
customer data, and security findings before posting.

## Suggest a feature or improve the documentation

Open an issue describing the problem and the workflow you want to support.
Documentation corrections and safe examples are welcome.

## Report a security issue

Report Codex Security vulnerabilities privately as described in
[SECURITY.md](SECURITY.md). Do not post vulnerabilities, exploit details,
credentials, or sensitive scan results publicly.

If a scan finds a vulnerability in another project, report it to that
project's maintainers through their security policy.

## Dependency and release maintenance

Maintainers update package dependencies and the committed lockfile in the
canonical repository. The public release workflow installs that locked graph,
tests the package, and publishes a verified artifact with npm provenance.
GitHub Actions dependencies are maintained separately in this repository.

The `node-release-pr` workflow proposes the next patch version when the current
`main` commit has passed `node-ci` and the packaged files have changed since the
current release. It waits for that version's npm publication, `npm-vX.Y.Z` tag,
and GitHub Release to finish. A successful `node-github-release` run retries the
check if publication was still pending. The PR changes only the version in
`sdk/typescript/package.json`. The bot preserves existing release PRs, including
manual minor or major releases, and does not reopen or recreate a closed bot PR
for the same version. It never merges, tags, publishes, or dispatches a release
workflow.

Generated PR descriptions use the full, static pull request template without
copying source history. A maintainer must review the complete public PR, finish
the disclosure checklist, and satisfy the usual review and CI requirements
before merging. The existing protected release process still controls
publication.

To enable the bot, allow GitHub Actions to create pull requests in the
repository's Actions settings. By default it uses `GITHUB_TOKEN`; a maintainer
must select **Approve workflows to run** on each generated PR before its CI can
start. For unattended CI, install a GitHub App on this repository with Actions
read, Contents write, and Pull requests write permissions. Set the repository
variable `RELEASE_APP_CLIENT_ID` to the App's client ID and the repository secret
`RELEASE_APP_PRIVATE_KEY` to its private key. A configured client ID without a
working private key fails the workflow instead of falling back to
`GITHUB_TOKEN`. The bot does not need npm credentials or OIDC permissions.

To preview the decision without creating a branch or PR, manually run
`node-release-pr` from `main` with `dry_run` enabled. For a local preview, check
out `main`, set `GITHUB_REPOSITORY` and `GH_TOKEN`, and run
`node sdk/typescript/scripts/patch-release-pr.mjs --dry-run` from the repository
root with Node.js 24.15.0.
