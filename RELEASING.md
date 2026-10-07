# Releasing BinHardS

BinHardS uses explicit release levels with automatic changelog generation.

## Prerequisites

Install the release tools once:

```bash
cargo install cargo-release --version 1.1.5 --locked
cargo install git-cliff --version 2.14.2 --locked
```

Make sure the working tree is clean and the local `main` branch is up to date.

## Release a patch

Preview the release first:

```bash
cargo release patch
```

When the preview is correct, execute it:

```bash
cargo release patch --execute
```

## Release a minor version

```bash
cargo release minor
cargo release minor --execute
```

## Release a major version

```bash
cargo release major
cargo release major --execute
```

## What the release command does

For an explicit release level, `cargo-release`:

1. Bumps the version in `Cargo.toml`.
2. Updates the lockfile as required by Cargo.
3. Runs `git-cliff` to generate the new release section in `CHANGELOG.md`.
4. Creates the release commit.
5. Creates the `vX.Y.Z` git tag.
6. Pushes the commit and tag.

The release configuration sets `publish = false`, so the local command does not publish to crates.io.

## What happens after the tag is pushed

The `vX.Y.Z` tag triggers `.github/workflows/release.yml`.

The release workflow:

1. Validates formatting, linting, tests, and packaging.
2. Verifies that the git tag matches the Cargo package version.
3. Performs the crates.io publish using Trusted Publishing and GitHub OIDC.
4. Creates the GitHub Release only after the crates.io publish succeeds.

No crates.io token is required on the developer machine.

## Release responsibility

Contributors describe and commit their changes normally. They do not choose the next version through commit-message syntax.

The maintainer chooses the release level explicitly:

- `patch`: backward-compatible bug fixes and other patch-level changes.
- `minor`: backward-compatible new functionality.
- `major`: breaking changes.

The release tooling handles the mechanical work after that decision.
