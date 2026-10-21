---
name: crypt-age-proof
description: "Use when proving a Crypt::Age change — the upstream age test kit (t/07-testkit.t), the interop suite against the real age and rage binaries (t/04-interop.t), what a green run shows, and which binary proved what."
---

# Crypt::Age — proving a change

The format and its constants live in `crypt-age-core`. The house rule is in
`.claude/rules/crypt-age-rules.md`: never report a green suite as evidence for a format-touching
change, and never weaken a check to make a test pass. This skill carries the mechanics behind that
rule.

## Never assume whether a binary is present — check

`which age rage` — machines differ and this skill ships inside the tarball, so any claim about what
is installed would be wrong somewhere. `t/04-interop.t` collects every CLI it finds — `age` and
`rage` — and runs the whole block once per CLI, prefixing each description with `[age]` / `[rage]`;
it `plan skip_all`s only when neither exists.

**Do instead:** say which of the three commands you ran, and against which binaries and versions. A
skip is not a pass.

## The counts tell you what ran

- With no binary the file asserts **nothing**, and a green suite is not evidence for a
  format-touching change on its own.
- With both installed the count is **120** (60 per CLI); with one, 60. A run reporting 60 covered a
  single implementation, and the `Using CLI:` diag lines at the top name which. No `PATH` surgery is
  needed to reach the Rust side any more.
- The two differ observably: given a 0-byte plaintext and `-o`, `age` writes a 0-byte file, `rage`
  writes no file at all. The chunk-boundary block handles both.

## The test kit proves the read side only

`t/07-testkit.t` is what fills the hole of a machine without a binary: the C2SP/CCTV vectors,
vendored under `t/testkit/`, 68 of 143 runnable against this implementation and 75 skipped with a
printed per-reason tally (armor, scrypt, hybrid — none implemented). They were produced by the
reference implementation, so they prove the read side against real bytes.

They cannot prove the write side end to end: there is no reproducible way to inject our randomness,
so nothing here shows that `age` accepts what we emit. Only the binary does that. A Perl→Perl
round-trip proves nothing either — our writer and our reader change together.

**Never edit a vector or the runner's expectations to get to green** — a test kit you adjust proves
nothing.

## Where the rest of the conventions live

- the format, the constants and the MAC invariant — `crypt-age-core`
- house style, `$VERSION`, cpanfile pinning — `getty-perl-core`, `getty-perl-moo`
- POD — `getty-perl-pod`
- the house rules — `.claude/rules/crypt-age-rules.md`
