# Crypt::Age House Rules

Apply to every task in this repository unless explicitly overridden. Bias: caution over
speed on non-trivial work; use judgment on trivial tasks. Loaded automatically at launch
(same priority as `CLAUDE.md`). Subagents get their conventions from the skills
force-loaded via `briefing.skills` — this file is for the orchestrating agent.

## Engineering discipline

1. **Think before coding** — State assumptions. When uncertain, ask rather than guess.
   Push back when a simpler approach exists. Stop when confused; name what's unclear.
2. **Simplicity first** — Minimum code that solves the problem. Nothing speculative.
3. **Surgical changes** — Touch only what you must. Don't "improve" adjacent code,
   comments or formatting. Match existing style.
4. **Read before you write** — Read the spec section before the code that implements it.
   Every constant in this distribution is dictated by `c2sp.org/age`, so "this looks
   wrong" is usually "I haven't read why yet".
5. **Tests verify intent, not just behavior** — Reproduce a bug before fixing it; leave
   a regression test behind. A test that can't fail when the wire format changes is not
   a test of this distribution.
6. **Match the codebase's conventions, even if you disagree** — Conformance > taste.
   Surface a harmful convention; don't fork silently.
7. **Fail loud** — "Done" is wrong if anything was skipped silently. "Tests pass" is
   wrong if any were skipped. Surface uncertainty, don't hide it.
8. **A red test is a claim before it is a failure** — Before changing code to turn a
   test green, say what the test asserts and whether your fix keeps that claim or
   replaces it. If the claim is wrong, fix the claim and say so.

## Delegation

Depends on whether the Agent/Task tool is available to you.

- **You can spawn subagents** (orchestrating main agent): Do NOT touch behavior-relevant
  code yourself — delegate. Your lane: coordinate, inspect, plan, review diffs, run
  tests, manage git, edit non-behavioral docs. Why: only the `crypt-age-*` agents get
  their skills force-loaded via `briefing.skills`; you get no briefing and would touch
  format-critical crypto with too little context.

  | Task | Agent |
  |---|---|
  | Implement / refactor / debug anything under `lib/` | `crypt-age-worker` (default) |
  | Write/extend tests, reproduce interop failures | `crypt-age-test-writer` |
  | Pre-release audit | `crypt-age-release-checker` |
  | POD | `crypt-age-doc-writer` |

- **You cannot spawn subagents** (you ARE a `crypt-age-*` agent): The delegation lock
  does not apply — implement, refactor, debug and test per these rules.

Behavior-relevant = anything under `lib/`, the tests, and any change to the header text,
MAC computation, key derivation, stanza serialization, Bech32 encoding or payload
chunking. `README.md` and `Changes` wording are not.

## Interop is the product — a green suite is not a proof

This distribution's entire claim is that `age` and `rage` can read what it writes.
`t/04-interop.t` is the only test that checks it, and it `plan skip_all`s when neither
binary is on PATH. Without one the suite reports `All tests successful` having asserted
nothing about compatibility.

Never report a green suite as evidence for a format-touching change. State which ran:

```bash
prove -lr t/               # unit only; -r matters, plain -l t/ is not recursive
prove -lv t/04-interop.t   # the actual proof (age 1.1.1 is on PATH here)
```

Self-consistency is the failure mode, not the safety net: this library decrypting its
own output proves nothing about what `age` will accept.

## The header MAC rides on re-serialization

`Header::verify_mac` re-runs the parsed stanzas through `Stanza::to_string` and MACs
*that*, not the bytes it read. So a change to stanza formatting — spacing, the 64-column
wrap, the base64 — is a wire change that will reject files written by `age`, while every
Perl→Perl test stays green. Treat `Stanza::to_string` as crypto, not as formatting.
Details and the full constant table: skill `crypt-age-core`.

## Cryptographic code — no drive-by changes

Nonce sizes, HKDF labels, key lengths and the MAC boundary are specified by
`c2sp.org/age`, not chosen here. Anything that looks wrong (a 16-byte file key, an
all-zero AEAD nonce, a MAC that excludes the trailing newline) is far more likely to be
a deliberate compatibility requirement than a bug — verify against the spec and the
binary before "fixing" it, and never weaken a check to make a test pass. Keys,
identities and plaintext never land in logs, commit messages or ticket bodies.

## Coordination — karr board (always in scope)

Ticket coordination is the orchestrating agent's job, so `karr` is always in scope —
don't invoke the skill first, just use it. Board state lives in `refs/karr/*`.

- `karr list --compact` / `karr board` — open work · `karr show ID` — detail
- `karr create "Title" --priority high --tags a,b --body '…'` — new ticket
- `karr edit ID -a "note"` · `--claim NAME` · `--block "why"` — update
- `karr move ID in-progress --claim NAME` — start · `karr handoff ID --claim NAME --note "…"` — to review

Serialize board mutations when fanning out: keep implementation parallel, then loop the
`karr move`/`handoff`/`sync` calls sequentially. Full command surface: skill `karr`.

## Release — never without permission

`dzil build` / `dzil test` / `prove -lr t/` are fine anytime. `dzil release` and any CPAN
upload are STRICTLY forbidden without the maintainer's explicit go-ahead — even if a plan
lists "release" as the next step. Stop and ask.

This distribution is an **upstream**: `File::SOPS` and `kubernetes-ocp` pin `Crypt::Age`
in their `cpanfile`s. A release here leaves those pins stale — that is a ticket on the
other repo's board, never an edit made from here.

## GitHub issues — never act without instruction

`karr` is the internal agent board, churned freely. GitHub issues on
`Getty/p5-crypt-age` are the **public tracker**: real people's reports, written under the
maintainer's account. Never act on one on your own initiative — not even to read it. No
listing, viewing, commenting, closing or creating unless the user explicitly says to
handle a specific issue.

## Perl specifics — reference, don't restate

Module loading, Moo patterns, cpanfile pinning for Getty-authored dependencies, POD
conventions and house style live in skills `perl-core`, `perl-moo` and
`perl-release-author-getty` (force-loaded for `crypt-age-*` agents). The age wire format
and its invariants live in skill `crypt-age-core`. Do not duplicate them here.
