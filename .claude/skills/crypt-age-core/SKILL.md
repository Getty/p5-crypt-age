---
name: crypt-age-core
description: "Load before editing Crypt::Age — the pure-Perl age implementation: header layout and MAC re-serialization, X25519 stanzas, Bech32 keys, STREAM chunking, the known spec gaps."
---

# Crypt::Age — core

Pure-Perl implementation of the age file encryption format, byte-compatible with the Go
reference implementation (`filippo.io/age`) and Rust `rage`. Interop is the whole
product: every constant here exists because the spec says so, not because it was chosen.

**The specification is normative and short — read it rather than guessing:**
<https://github.com/C2SP/C2SP/blob/main/age.md> (`c2sp.org/age`). Where this skill and
the spec disagree, the spec wins and this file is the bug.

## Module map

| Module | Owns |
|---|---|
| `Crypt::Age` | public API — `generate_keypair`, `encrypt`/`decrypt`, `encrypt_file`/`decrypt_file`. Class methods, never instantiated |
| `Crypt::Age::Header` | the text header — `create`, `parse`, `to_string`, `verify_mac`, `unwrap_file_key`, and `_header_bytes_for_mac` |
| `Crypt::Age::Stanza` | stanza base class — `to_string`, the 64-column body wrap, `encode_base64_no_padding` / `decode_base64_no_padding` |
| `Crypt::Age::Stanza::X25519` | `wrap` / `unwrap` for `-> X25519` stanzas (the only recipient type implemented) |
| `Crypt::Age::Keys` | Bech32 (BIP-173) encode/decode, `age` / `age-secret-key-` HRPs, `public_key_from_secret` |
| `Crypt::Age::Primitives` | X25519, ChaCha20-Poly1305, HKDF-SHA256, HMAC-SHA256, STREAM chunking, `_make_nonce` |

Everything is `Moo` + `namespace::clean`. `Crypt::Age` itself declares no attributes —
it is a `Moo` class used purely as a namespace for class methods. Don't "fix" that into
an instance API without a reason; callers depend on the class-method form.

## The file

```
age-encryption.org/v1\n          <- version line
-> X25519 <b64 ephemeral share>\n <- one stanza per recipient
<b64 wrapped file key>\n
--- <b64 mac>\n                   <- header ends here
<16-byte nonce><encrypted chunks> <- binary payload, no separator
```

## Wire constants — all specified, none chosen

| Thing | Value | Where |
|---|---|---|
| file key | **16 bytes** CSPRNG, never reused | `Primitives::generate_file_key` |
| X25519 wrap key | `HKDF-SHA256(ikm=shared_secret, salt=ephemeral_share‖recipient, info="age-encryption.org/v1/X25519")`, 32 bytes | `derive_wrap_key` |
| stanza body | `ChaCha20-Poly1305(wrap_key, file_key)` with a **12-byte all-zero nonce** → 32 bytes (16 ct + 16 tag) | `wrap_file_key` |
| header MAC key | `HKDF-SHA256(ikm=file_key, salt="", info="header")` | `compute_header_mac` |
| header MAC | HMAC-SHA256 over the header **up to and including `---`**, excluding the space after it and with **no trailing newline** | `_header_bytes_for_mac` |
| payload nonce | 16 bytes CSPRNG, sits immediately after the header's newline | `generate_payload_nonce` |
| payload key | `HKDF-SHA256(ikm=file_key, salt=nonce, info="payload")` | `derive_payload_key` |
| chunking | 64 KiB, ChaCha20-Poly1305, nonce = 11-byte big-endian counter ‖ `0x01` final / `0x00` otherwise | `encrypt_payload`, `_make_nonce` |
| base64 | RFC 4648 §4, **unpadded**, everywhere in the header | `Stanza` |

## The invariant that decides whether interop holds

**The header MAC is computed over a *re-serialization*, not over the bytes that were
read.** `Header::parse` builds `Stanza` objects and `verify_mac` then calls
`_header_bytes_for_mac`, which runs every stanza back through `Stanza::to_string`.

The consequence, and it is the single most important thing to know about this
distribution:

> Any change to how a stanza is formatted — argument spacing, the 64-column wrap, the
> base64 encoding, the order of stanzas — is a **wire change**. It will make files
> written by `age` fail their own MAC here, even though nothing about the crypto moved.

So a "cosmetic" edit in `Stanza::to_string` is never cosmetic. Round-tripping Perl→Perl
will keep passing, because our writer and our reader change together. Only the real
binary catches it. This is why `t/04-interop.t` is the only test that means anything
for this layer.

A parse-time capture of the literal header bytes would remove the coupling, and that is
a real design option — but it is a change with consequences, so make it deliberately and
write it down, don't slide into it while fixing something else.

## Known spec gaps — measured, not speculated

These are all verified against `age` 1.1.1 and the C2SP spec text. They are open work,
not accepted behaviour. Do not "discover" them again — check the karr board first, and
if you fix one, close its ticket.

1. **The all-zero shared secret is not rejected.** The spec: *"If the shared secret is
   all 0x00 bytes, the identity implementation MUST abort."* `Primitives::x25519_shared_secret`
   returns it happily — verified: a 32-byte all-zero peer key yields a 32-byte all-zero
   secret from CryptX, and `Stanza::X25519::unwrap` proceeds to derive a wrap key from
   it. This is the low-order-point check; its absence is a security defect, not a
   cosmetic gap.

2. **A stanza body that is an exact multiple of 64 base64 characters emits no final
   line.** The ABNF is `stanza = arg-line *full-line final-line` with
   `final-line = *63base64char LF` — an empty final line is *required* when the body
   ends flush at 64 columns. `Stanza::to_string` uses `while (length($body_b64) > 64)`,
   so a 64-char body produces one 64-char line and stops. Unreachable today (an X25519
   body is 32 bytes → 43 chars) and immediately reachable for any recipient type with a
   48/96-byte body. `Header::parse`'s `last if length($body_line) < 64` is the matching
   half and reads it correctly — the writer is the broken side.

3. **The base64 decoder accepts what the spec says it MUST reject.**
   `decode_base64_no_padding` adds padding back before decoding, so padded and
   non-canonical encodings are accepted. The spec: *"decoders MUST reject non-canonical
   encodings and encodings ending with `=` padding characters."*

4. **Stanza arguments are not validated.** The spec requires rejecting an X25519 stanza
   with other than exactly two arguments, or whose second argument is not a canonical
   base64 encoding of a 32-byte value. `Header::parse` splits on whitespace and hands
   whatever it finds to `unwrap`.

5. **An empty payload decrypts to the empty string instead of erroring.**
   `decrypt_payload`'s `while ($remaining > 0)` never runs for a zero-byte payload, so a
   truncated file that lost its whole payload verifies as an empty plaintext. The spec:
   *"Streaming decryption MUST signal an error if the end of file is reached without
   successfully decrypting a final chunk."* (Truncation at any *other* point does fail
   correctly — the final-flag byte lands in the nonce and the tag check catches it.)

6. **`verify_mac` compares with `eq`**, not in constant time.

7. **`_make_nonce` computes its nonce twice.** The first `pack('x3 N N', …)` is
   overwritten on the next line and is dead. The surviving code is correct; the corpse
   is confusing.

Also absent by design so far, not defects: scrypt / passphrase recipients, the ssh and
`mlkem768x25519` / tagged types, ASCII armor, and streaming (both `encrypt_file` and
`decrypt_file` slurp the whole file into memory).

## Keys

Bech32 per BIP-173, **without** the 90-character length limit (the spec removes it).
HRP `age` for recipients (lowercase output), `age-secret-key-` for identities
(**uppercased** on output — `encode_secret_key` wraps the whole string in `uc`).
The checksum is always computed over the lowercase form, which is why `bech32_decode`
lowercases the HRP before verifying.

`Keys::decode_*` does not reject mixed-case strings; the spec allows all-upper or
all-lower only.

## Proof — a green suite is not one

```bash
prove -lr t/                    # unit tests; note -r, plain -l t/ is not recursive
prove -lv t/04-interop.t        # the only compatibility proof
```

`t/04-interop.t` resolves the CLI with `which age` and falls back to `which rage`, then
`plan skip_all` if neither exists. Without a binary the suite reports *All tests
successful* having skipped every compatibility assertion. **Always say which of the two
you ran**, and treat "interop skipped" as an unverified change, not a passing one.

`age` 1.1.1 is on PATH on this machine. The upstream test kit at
<https://age-encryption.org/testkit> is not wired into the suite yet — it is the
authoritative vector set and a real gap.

Never weaken an assertion to make a test pass. Keys, identities and plaintext never
appear in errors, diagnostics, commit messages or ticket bodies.
