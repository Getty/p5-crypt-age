# Crypt::Age House Rules

The shared house rules come from skilletor — bundle `getty-cpan-dist@getty`: engineering
discipline, the delegation lock, the publish gate, karr coordination, CPAN release. They load
as `.claude/rules/.local.*.md`; if they are missing, run `skilletor sync` and publish nothing
until they load. This file adds what is true only here, and wins where it differs.

## What this repo is

Perl implementation of age encryption (age-encryption.org). Read first: the spec section
before the code — every constant here is dictated by `c2sp.org/age`, so "looks wrong" usually
means "I haven't read why yet".

## Agent team

| Task | Agent |
|---|---|
| Implement / refactor / debug anything under `lib/` | `crypt-age-worker` (default) |
| Write/extend tests, reproduce interop failures | `crypt-age-test-writer` |
| Commits, `Changes`, card → done, pre-release audit | `crypt-age-release-manager` |
| POD | `crypt-age-doc-writer` |
| Read-only research, audit, gap analysis | `crypt-age-worker` ("read-only, change nothing") |

Behavior-relevant = `lib/`, the tests, and any change to header text, MAC, key derivation,
stanza serialization, Bech32 encoding or payload chunking — not `README.md` or `Changes`
wording.

## Release

This distribution is an **upstream**: `File::SOPS` and `kubernetes-ocp` pin `Crypt::Age` in
their `cpanfile`s — a release here leaves those pins stale, and that is a ticket on the other
repo's board, never an edit made from here.

## Hazards — interop and crypto, the spec is the reference

- **Never report a green suite as evidence for a format-touching change.** `t/04-interop.t` is
  the only proof against the real binaries; it `skip_all`s when neither `age` nor `rage` is on
  PATH — check with `which age rage`, say which binary ran, never report it as run when it
  skipped. Self-consistency proves nothing; a test that can't fail when the wire format changes
  is no test here.
- **`t/07-testkit.t` covers the read side only** — it runs the upstream vectors without a
  binary; the write side needs the binary. Stanza formatting is a wire change: spacing, the
  64-column wrap and the base64 decide the bytes `age` has to accept, and every Perl→Perl test
  stays green through it. Details and the constant table: skill `crypt-age-core`.
- **Nonce sizes, HKDF labels, key lengths and the MAC boundary are specified by `c2sp.org/age`**,
  not chosen here. What looks wrong is more likely a deliberate compatibility requirement than
  a bug — verify against the spec and the binary before "fixing" it; **never weaken a check to
  make a test pass**.
- **Keys, identities and plaintext never land** in logs, commit messages or ticket bodies.

## Perl specifics — reference, don't restate

House Perl style lives in `getty-perl-core`, `getty-perl-moo`, `getty-perl-release-author-getty`;
the age wire format in `crypt-age-core` (force-loaded for `crypt-age-*` agents).
