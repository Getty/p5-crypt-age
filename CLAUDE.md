# Crypt::Age

Pure Perl implementation of the age file encryption format
([age-encryption.org/v1](https://age-encryption.org)), compatible with the reference Go
implementation (`filippo.io/age`) and the Rust implementation (`rage`).

Released to CPAN as `Crypt-Age`. Built and released with `Dist::Zilla` via
`[@Author::GETTY]`.

## Specification

- Format spec: <https://github.com/C2SP/C2SP/blob/main/age.md> (`c2sp.org/age`)
- Test vectors: <https://age-encryption.org/testkit> (authoritative; vendored under
  `t/testkit/` and run by `t/07-testkit.t`)

The spec is normative and short. Read the relevant section before changing any constant
— every size, label and offset in this distribution is dictated by it.

## Status

X25519 recipients are implemented end to end: keypair generation, header creation and
parsing, the header MAC, and the STREAM-chunked payload. Verified against `age` 1.1.1
on a machine that had it, and on every push against the 143 upstream test vectors —
68 of which exercise this implementation, the rest covering features it does not have.

Not implemented: scrypt/passphrase recipients, SSH recipients, the post-quantum and
tagged recipient types, ASCII armor, and streaming I/O (`encrypt_file` / `decrypt_file`
read the whole file into memory).

The architecture, the full wire-constant table and the measured deviations from the spec
live in skill `crypt-age-core` — they are not repeated here.

## Build and test

```bash
dzil build          # build the distribution
dzil test           # recursive test run
dzil clean          # clean build artifacts
prove -lr t/        # everything — note -r, plain `prove -l t/` is not recursive
prove -lv t/07-testkit.t   # 143 upstream vectors; needs no age binary
prove -lv t/04-interop.t   # the real binary; skips without one
```

`t/04-interop.t` calls `plan skip_all` when neither `age` nor `rage` is on PATH, and
then asserts nothing about compatibility. `t/07-testkit.t` needs no binary and prints
what it ran and what it skipped. Always say which of the runs you did.

## Delegation

Delegate behavior-relevant code to the right agent instead of touching it yourself — the
principle and the lane boundaries are in `.claude/rules/crypt-age-rules.md`.

| Task | Agent |
|---|---|
| Implement / refactor / debug anything under `lib/` | `crypt-age-worker` (default) |
| Write/extend tests, reproduce interop failures | `crypt-age-test-writer` |
| Pre-release audit | `crypt-age-release-checker` |
| POD | `crypt-age-doc-writer` |

The agents carry their skills via `briefing.skills` (see `.claude/agents/`); the main
agent delegates rather than loading them. Skill sources live under `.claude/skills/` —
`getty-perl-core`, `getty-perl-moo`, `getty-perl-release-author-getty` and `perl-release-dist-ini` are
hardlinked from `~/dev/skills/perl/`; `crypt-age-core` is owned by this repo.

Work is coordinated on the repo's `karr` board (`karr board`).

`.claude/` and this file ship inside the CPAN tarball on purpose — the distribution
discloses how it was built. There is deliberately no `gather_exclude_match` in
`dist.ini`; `.gitignore` is what keeps credentials, session state and machine-local
overrides out, since `Git::GatherDir` ships tracked files only.

## Downstream

`File::SOPS` and `kubernetes-ocp` pin `Crypt::Age` in their `cpanfile`s. A release here
leaves those pins stale — file that as a ticket on the other repo's board, never as an
edit from here.
