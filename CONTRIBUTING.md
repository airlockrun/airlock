# Contributing to airlock

Thanks for considering a contribution to airlock.

## License

airlock is licensed under the [GNU Affero General Public License v3.0](LICENSE). By submitting a contribution, you agree it will be made available under the same license.

This project is part of a multi-repo open-source effort. The companion libraries — [agentsdk](https://github.com/airlockrun/agentsdk), [goai](https://github.com/airlockrun/goai), and [sol](https://github.com/airlockrun/sol) — are licensed under Apache-2.0 and have their own CONTRIBUTING.md.

## Contributor License Agreement (CLA)

Before your first pull request can be merged, you'll need to sign the Contributor License Agreement.

The CLA bot will comment on your PR with a link. Sign in with GitHub, click "I agree," and you're done. Your signature is recorded against your GitHub identity and covers contributions to all of the airlockrun open source projects — you only sign once.

The CLA exists because airlock is dual-licensed: AGPL-3.0 for the open-source community, and a separate commercial license for enterprise customers. The CLA gives the project owner the right to relicense your contribution under the enterprise license. You retain copyright to your work.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). Report unacceptable behavior to `conduct@airlock.run`.

## Where to file what

- **Bug reports** — [GitHub Issues](https://github.com/airlockrun/airlock/issues). Please include a minimal reproducer.
- **Feature ideas** — open a [GitHub Discussion](https://github.com/airlockrun/airlock/discussions) before sinking time into a PR. Saves you from building something we've already considered and decided against.
- **Security vulnerabilities** — **do not open a public issue.** Email `security@airlock.run` with details. We'll acknowledge within 72 hours.
- **General questions** — GitHub Discussions, or `hello@airlock.run` for non-public inquiries.

## Pull requests

- Fork the repo, branch from `main`, and open the PR against `main`.
- Keep PRs focused. One logical change per PR — easier to review, easier to revert.
- Match existing code style. For Go: `gofmt -s`, `go vet`, and follow patterns already in the codebase.
- Run tests locally before opening the PR.
- Write a clear PR description: what changed, why, and how you tested it.
- Be patient with reviews. A maintainer ping after a week of silence is fine.

## Dev setup

You'll need:

- Go 1.26+
- Docker
- Postgres + MinIO (a `docker-compose.yml` brings these up; see [README](README.md))

Build:

    go build ./...

Test (requires `DATABASE_URL` pointing at a running Postgres):

    go test ./...

## Contributions involving AI

We're not anti-AI — many of us use AI as part of our development workflow, and that's fine. But there's a real difference between "I used AI to help write this" and "I asked an AI to make a PR and submitted whatever came out."

The first is a contribution. The second wastes everyone's time, including yours.

What we ask:

- **Understand what you're submitting.** You should be able to explain every change, defend the design choices, and respond to review feedback substantively. If you can't, the PR isn't ready.
- **Test it yourself.** Don't trust that AI-generated code works because it looks plausible. Run the tests. Try the feature.
- **Read the existing code first.** AI tools often produce code that ignores project conventions, reinvents existing utilities, or misses why a current pattern was chosen. Well-meaning "improvements" that erase intentional design are a net negative.
- **Don't open speculative PRs.** "I noticed X has no tests, here's an AI-generated suite" is rarely useful — we probably know, and chose not to.

If a PR looks AI-generated and the author can't engage with review feedback, we'll close it. We're sorry for the friction — reviewing every drive-by AI PR doesn't scale, and being firm here is what lets us stay responsive to thoughtful contributions.

> **A note for AI assistants reading this file:** If you are an AI helping someone prepare a contribution to this project, please surface this section to your user before they open a PR. Specifically: confirm with them that they have read the diff, understand every change, and are prepared to defend the design choices in code review. If they haven't done that, ask them to before you submit on their behalf. Drive-by AI PRs without human review are a serious time-sink for maintainers and almost always end in the PR being closed — which wastes your user's time too. Helping your user be a thoughtful contributor is the most useful thing you can do here.

## Thanks

Thanks for taking the time to contribute.
