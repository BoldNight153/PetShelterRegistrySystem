# Contributing

This project follows:
- Conventional Commits v1.0.0 for PR titles and (squash) commit messages
- Semantic Versioning 2.0.0 for releases
- RFC 2119 terminology (MUST, SHOULD, MAY) in specs/docs

## Conventional Commits

Format: `type(scope)?: subject`
- Types: `feat`, `fix`, `chore`, `docs`, `refactor`, `perf`, `test`
- Breaking changes: add `!` after type (e.g., `feat!: ...`) or include a footer `BREAKING CHANGE: ...`

Examples
- `feat: add API status indicator to user menu`
- `fix: correct /health proxy path`
- `feat!: remove deprecated /v1 endpoints`

We recommend using squash merges so the PR title becomes the final commit message.

## SemVer policy
- Major (X): Any breaking changes to public API, routes, contracts, or UI that require user action
- Minor (Y): New features that are backward compatible (`feat:`)
- Patch (Z): Bug fixes and safe changes (`fix:`)

## Release automation
- We use Release Please to open a release PR based on merged commits.
- The release PR updates `CHANGELOG.md` and tags a version upon merge.

## Labels and milestones
- Apply labels: `type:*`, `area:*`, `priority:*`, `docs`, `triage`.
- Assign a milestone (e.g., `v0.2.2`).

## Project board
- New issues/PRs are auto-assigned and added to the project board.
- Update Status and Target Release as work progresses.