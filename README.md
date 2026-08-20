# Crypt::Age

Perl implementation of the [age encryption format](https://age-encryption.org).

## Synopsis

```perl
use Crypt::Age;

# Generate a keypair
my ($public_key, $secret_key) = Crypt::Age->generate_keypair();
# $public_key = "age19ljhmg68e43yx9fgm2k9lwefquc0la5y4lzvlshdjzv47kxt8d6qr9vf4p"
# $secret_key = "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ8H00W3"

# Encrypt data
my $encrypted = Crypt::Age->encrypt(
    plaintext  => "Hello, World!",
    recipients => [$public_key],
);

# Decrypt data
my $decrypted = Crypt::Age->decrypt(
    ciphertext => $encrypted,
    identities => [$secret_key],
);

# Encrypt a file
Crypt::Age->encrypt_file(
    input      => 'secret.txt',
    output     => 'secret.txt.age',
    recipients => [$public_key],
);

# Decrypt a file
Crypt::Age->decrypt_file(
    input      => 'secret.txt.age',
    output     => 'secret.txt',
    identities => [$secret_key],
);

# Encrypt and decrypt through filehandles
Crypt::Age->encrypt_filehandle(
    input      => \*STDIN,
    output     => \*STDOUT,
    recipients => [$public_key],
);
Crypt::Age->decrypt_filehandle(
    input      => \*STDIN,
    output     => \*STDOUT,
    identities => [$secret_key],
);
```

## Description

age is a simple, modern and secure file encryption tool with small explicit keys, no config options, and UNIX-style composability.

This module provides a pure Perl implementation of the age encryption format, interoperable with:

- [age](https://github.com/FiloSottile/age) - The reference Go implementation
- [rage](https://github.com/str4d/rage) - A Rust implementation

Files encrypted with Crypt::Age can be decrypted with these tools and vice versa, for the
X25519 recipient type. The other recipient types the format defines are not implemented
here - see [Current Limitations](#current-limitations).

## Features

- X25519 key exchange for secure key agreement
- ChaCha20-Poly1305 AEAD for authenticated encryption
- HKDF-SHA256 for key derivation
- Bech32 key encoding (age1.../AGE-SECRET-KEY-1...)
- Multiple recipients support
- Binary-safe encryption
- STREAM payload chunking in 64 KiB chunks
- Streaming file and filehandle API; the string API `encrypt`/`decrypt` holds the whole
  message in memory

## Key Format

### Public Keys

Public keys are Bech32-encoded with the human-readable part `age`:

```
age19ljhmg68e43yx9fgm2k9lwefquc0la5y4lzvlshdjzv47kxt8d6qr9vf4p
```

### Secret Keys

Secret keys are uppercase Bech32-encoded with the human-readable part `AGE-SECRET-KEY-`:

```
AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ8H00W3
```

## Installation

```bash
cpanm Crypt::Age
```

Or manually:

```bash
perl Makefile.PL
make
make test
make install
```

## Dependencies

- [CryptX](https://metacpan.org/pod/CryptX) - Provides X25519, ChaCha20-Poly1305, HKDF, and HMAC
- [Moo](https://metacpan.org/pod/Moo) - Object system

## Testing

```bash
# Run all tests (-r matters, plain -l t/ is not recursive)
prove -lr t/

# Verbose output
prove -lvr t/

# Run a specific test
prove -lv t/02-encrypt-decrypt.t
```

Two of the test files carry the compatibility claim:

- `t/07-testkit.t` runs the 143 vectors of the upstream
  [age test kit](https://age-encryption.org/testkit), vendored under `t/testkit/`. It
  needs no binary on `PATH`. 68 of them exercise this implementation; the remaining 75
  are skipped with a stated reason, since they cover ASCII armor and the scrypt and
  post-quantum recipient types, none of which are implemented here.
- `t/04-interop.t` drives the real `age` and `rage` binaries in both directions. It runs
  its whole block once per CLI it finds, tagging each assertion `[age]` or `[rage]`, and
  skips entirely when neither is installed. With both installed it reports 120 tests, 60
  per implementation - a run of 60 covered only one of them.

Both binaries are worth having installed, since each is exercised separately:

```bash
# Install age (on macOS)
brew install age

# Install rage (via cargo)
cargo install rage
```

## Specification

This implementation follows the [age specification](https://github.com/C2SP/C2SP/blob/main/age.md).

### File Format

An age-encrypted file consists of:

1. **Header** (text) - Version, recipient stanzas, and MAC
2. **Payload** (binary) - ChaCha20-Poly1305 encrypted content in 64KB chunks

```
age-encryption.org/v1
-> X25519 <ephemeral-public-key-base64>
<wrapped-file-key-base64>
--- <header-mac-base64>
<binary encrypted payload>
```

## Cryptographic Primitives

| Primitive | Purpose |
|-----------|---------|
| X25519 | Key exchange between sender and recipient |
| ChaCha20-Poly1305 | Authenticated encryption of file key and payload |
| HKDF-SHA256 | Key derivation for wrap key, payload key, and MAC key |
| HMAC-SHA256 | Header authentication |

## Current Limitations

- Only X25519 recipients are supported. Not implemented: scrypt (passphrase) recipients,
  SSH recipients, and the post-quantum/tagged types such as `mlkem768x25519`. A file
  using one of those cannot be decrypted here and raises an error.
- No armored (PEM-like) output format
- No plugin support

## See Also

- [age-encryption.org](https://age-encryption.org) - Official age homepage
- [age specification](https://github.com/C2SP/C2SP/blob/main/age.md) - Format specification
- [filippo.io/age](https://pkg.go.dev/filippo.io/age) - Go implementation docs

## Author

Torsten Raudssus <torsten@raudssus.de>

## License

This is free software; you can redistribute it and/or modify it under the same terms as the Perl 5 programming language system itself.
