---
name: perl-crypt-age
description: Use when calling Crypt::Age from another project — encrypt/decrypt to age1 recipients, generate_keypair, validating key strings, passphrase requests, age/rage interop.
---

# Crypt::Age — calling it

Pure-Perl [age](https://age-encryption.org) encryption (CryptX underneath). All entry points are class
methods with named arguments; the class is never instantiated. Pin **Crypt::Age >= 0.005** (see
*Topic variable*). Format internals and maintenance are `crypt-age-core`; proving changes is
`crypt-age-proof`.

## Scope: X25519 recipients only

There is **no passphrase / password mode**, no scrypt recipient and no armor. `encrypt` takes
`recipients` (public keys) and nothing else; `encrypt(plaintext => …, passphrase => …)` dies
`recipients required`. When a caller needs a password layer, build it outside age (e.g. a KDF plus
AEAD) and age-encrypt the result. Ciphertext is always binary; an armored file (`age -a`) and a file
whose recipients are all scrypt/SSH die on decrypt (`Invalid age version…` / `No matching identity found`).
A file with an X25519 stanza plus other types decrypts normally; unknown stanza types are skipped.

## Keys

```perl
my ($public, $secret) = Crypt::Age->generate_keypair;  # list: age1… (lowercase), AGE-SECRET-KEY-1… (uppercase)
```

- **recipients** are public keys (`age1…`), used to encrypt. **identities** are secret keys
  (`AGE-SECRET-KEY-1…`), used to decrypt. Both are ArrayRefs, even for one entry: `[$public]`.
- Case: all-lowercase or all-uppercase is accepted for both kinds (Bech32 rule); **mixed case dies**
  (`Invalid bech32: mixed case`). Trim whitespace first — a trailing `"\n"` dies with
  `Invalid bech32 character at offset N` (`chomp` key files).
- Validate a recipient string: `eval { Crypt::Age::Keys->decode_public_key($s); 1 }` (returns 32 raw
  bytes, dies on wrong HRP, bad checksum, wrong length). Validate an identity with
  `Crypt::Age::Keys->decode_secret_key($s)`. A secret key passed to `decode_public_key` dies
  `Invalid public key HRP…`, so the check also catches a swapped pair.
- Derive the recipient from an identity: `Crypt::Age::Keys->public_key_from_secret($secret)` — equals
  the `age1…` from `generate_keypair` (and what `age-keygen -y` prints).
- Error messages never quote the offending key (keys are secrets); match on the leading phrase.

## Encrypt / decrypt (in memory)

```perl
my $ct = Crypt::Age->encrypt(plaintext => $bytes, recipients => [$pub_a, $pub_b]);  # binary string
my $pt = Crypt::Age->decrypt(ciphertext => $ct,   identities => [$secret]);         # bytes
```

- Any one listed identity that matches any one recipient stanza opens the file; extra non-matching
  or non-key strings in `identities` are skipped. A malformed `AGE-SECRET-KEY-1…` string dies with a
  Bech32 error (e.g. `Invalid bech32 checksum`) once a stanza is tried against it, instead of "no match".
- **Bytes in, bytes out.** `plaintext` with a code point above 0xFF dies `plaintext must be a byte
  string…`; `encode('UTF-8', $text)` first, `decode` the result. Read ciphertext files `:raw`.
- Empty plaintext is fine. Missing arguments die `<name> required`; a bare string instead of an
  ArrayRef dies `recipients|identities must be an ArrayRef…`, an empty list `… must not be empty…`.
- Every failure dies (message in `$@`); there is no undef/false return. A decrypt that dies returns
  nothing, so no partial plaintext leaks.

## How failures surface (match with `like`/`=~` on the prefix)

| Cause | Message starts |
|---|---|
| no listed identity fits | `No matching identity found` |
| flipped bit / truncated payload / appended bytes | `Payload authentication failed at chunk N` (+ reason) |
| cut inside the header, not an age file, empty input | `Invalid age stanza…` / `Invalid age version…` (or `Invalid age file, no valid header MAC line`) |
| non-`age1` recipient | `Unsupported recipient format at index N: expected an age1 recipient` (+ `, got an AGE-SECRET-KEY-1 identity` when swapped) |
| header with > 128 stanzas | `age header carries more than 128 recipient stanzas…` |

`No matching identity found` also covers a file that was never encrypted to you, so offer "wrong key?"
as the user-facing hint. Raise the stanza cap with `max_stanzas => 1000` on any decrypt call (positive
integer; `0`/`undef` die); files this module writes stay far below it.

## Files and handles (large data)

`encrypt_file`/`decrypt_file` take `input`, `output` (paths), `encrypt_filehandle`/`decrypt_filehandle`
take open handles; all stream in 64 KiB chunks, return `1`, and take the same `recipients` /
`identities` (+ `max_stanzas` on decrypt). **A failed streaming decrypt leaves the already-authenticated
chunks in `output`**: write to a temp path or handle and rename or use it only after the call returns.
The in-memory pair holds everything in RAM; prefer the file pair above a few MiB.

## Interop with `age` / `rage`

Both directions hold for X25519 files: `age -d -i key.txt file.age` and `rage` decrypt Crypt::Age
output, and Crypt::Age decrypts `age -r age1…` / `rage -r` output, including multi-chunk sizes,
binary data and unknown ("grease") stanzas (`t/04-interop.t`, run against age 1.2.1 and rage 0.12.1).
Outside that: `-p` passphrase files and `-a` armor (see *Scope*), and files with more than 128
recipients unless `max_stanzas` is raised. A secret-key file for the CLIs is the `AGE-SECRET-KEY-1…`
line, which is also the bare string Crypt::Age wants.

## Topic variable

Every decrypt entry point leaves the caller's `$_` untouched from 0.005 on. Releases before it
overwrite `$_` while reading the header: `for (@files) { decrypt… }` rewrites the array elements and a
loop over literals dies `Modification of a read-only value attempted`. Hence the floor:
`requires 'Crypt::Age', '0.005';`.
