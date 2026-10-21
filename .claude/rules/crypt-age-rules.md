# Crypt::Age House Rules

Apply to every task here unless explicitly overridden. Bias: caution over speed on non-trivial work;
judgment on trivial ones. Subagents get their conventions from `briefing.skills` — skill content is
not restated here. House Perl style lives in `getty-perl-core`, `getty-perl-moo`,
`getty-perl-release-author-getty`; the age wire format in `crypt-age-core`.

## Engineering discipline

1. **Think before coding** — State assumptions; ask rather than guess when uncertain; offer
   alternatives if ambiguous. Push back if simpler exists; stop when confused, name what's unclear.
2. **Simplicity first** — Minimum code that solves the problem. Nothing speculative.
3. **Surgical changes** — Touch only what you must. Don't "improve" adjacent code, comments or
   formatting. Match existing style.
4. **Read before you write** — Read the spec section before the code: every constant here is
   dictated by `c2sp.org/age`, so "looks wrong" usually means "I haven't read why yet".
5. **Tests verify intent, not just behavior** — Reproduce a bug before fixing it; leave a regression
   test behind. A test that can't fail when the wire format changes is no test here.
6. **Match the codebase's conventions, even if you disagree** — Conformance > taste; surface a
   harmful convention, don't fork silently.
7. **Fail loud** — "Done" is wrong if anything was skipped silently. "Tests pass" is wrong if any
   were skipped. Surface uncertainty, don't hide it.
8. **A red test is a claim before it is a failure** — Before turning a test green, say what it
   asserts and whether your fix keeps or replaces that claim. If the claim is wrong, fix the claim.

## Delegation

This rule depends on whether the Agent/Task tool is available to you.

- **You can spawn subagents** (orchestrating main agent): Do NOT touch behavior-relevant code
  yourself — delegate. Your lane: coordinate, inspect, plan, review diffs, run tests, edit prose
  docs. Why: only the `crypt-age-*` agents get their skills via `briefing.skills`; you get none.

| Task | Agent |
|---|---|
| Implement / refactor / debug anything under `lib/` | `crypt-age-worker` (default) |
| Write/extend tests, reproduce interop failures | `crypt-age-test-writer` |
| Commits, `Changes`, card → done, pre-release audit | `crypt-age-release-manager` |
| POD | `crypt-age-doc-writer` |

- **You cannot spawn subagents** (you ARE a `crypt-age-*` agent): The delegation lock does not apply
  — implement, refactor, debug and test per these rules.

Behavior-relevant = `lib/`, the tests, and any change to header text, MAC, key derivation, stanza
serialization, Bech32 encoding or payload chunking — not `README.md` or `Changes` wording. **Only
`crypt-age-release-manager` commits**; workers hand over a commit-ready tree and their card.

## Interop and crypto — the spec is the reference

**Never report a green suite as evidence for a format-touching change.** `t/04-interop.t` is the
only proof against the real binaries; it `skip_all`s when neither `age` nor `rage` is on PATH —
check with `which age rage`, say which binary ran, never report it as run when it skipped.
Self-consistency proves nothing.

`t/07-testkit.t` runs the upstream vectors without a binary and covers the read side only — the
write side needs the binary. Stanza formatting is a wire change: spacing, the 64-column wrap and the
base64 decide the bytes `age` has to accept, and every Perl→Perl test stays green through it.
Details and the constant table: skill `crypt-age-core`.

Nonce sizes, HKDF labels, key lengths and the MAC boundary are specified by `c2sp.org/age`, not
chosen here. What looks wrong is more likely a deliberate compatibility requirement than a bug —
verify against the spec and the binary before "fixing" it; **never weaken a check to make a test
pass**. Keys, identities and plaintext never land in logs, commit messages or ticket bodies.

## Coordination — karr board (always in scope)

Ticket coordination is the orchestrating agent's job, so `karr` is always in scope — don't invoke
the `kanban-issues-karr-coordination` skill first, just use it. Board state lives in `refs/karr/*`.

- `karr list --compact` / `karr board` — open work · `karr show ID` — detail
- `karr create "Title" --priority high --body '…'` · `karr edit ID -a "note" --block "why"`
- `karr move ID in-progress --claim NAME` — start · `karr handoff ID --claim NAME --note` — review

**Serialize board mutations** — parallel implementation is fine, board writes one after another.

## Release — never without permission

`dzil build` / `dzil test` / `prove -lr t/` are fine anytime. `dzil release` and any CPAN upload are
STRICTLY forbidden without the maintainer's explicit go-ahead — even if a plan lists "release" next.
Stop and ask. This distribution is an **upstream**: `File::SOPS` and `kubernetes-ocp` pin
`Crypt::Age` in their `cpanfile`s — a release here leaves those pins stale, and that is a ticket on
the other repo's board, never an edit made from here.

## GitHub issues — never act without instruction

`karr` is the internal board. GitHub issues on `Getty/p5-crypt-age` are the **public tracker** —
real people's reports under the maintainer's account. **Never act on one on your own initiative —
not even to read it.** No listing, viewing, commenting, closing or creating unless told to handle
one.
