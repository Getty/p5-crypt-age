package Crypt::Age;
# ABSTRACT: Perl implementation of age encryption (age-encryption.org)

use Moo;
use Carp qw(croak);
use Crypt::Age::Keys;
use Crypt::Age::Primitives;
use Crypt::Age::Header;
use namespace::clean;

=head1 SYNOPSIS

    use Crypt::Age;

    # Generate keypair
    my ($public, $secret) = Crypt::Age->generate_keypair();
    # $public  = "age1ql3z7hjy..."
    # $secret  = "AGE-SECRET-KEY-1..."

    # Encrypt data
    my $encrypted = Crypt::Age->encrypt(
        plaintext  => "Hello, World!",
        recipients => [$public],
    );

    # Decrypt data
    my $decrypted = Crypt::Age->decrypt(
        ciphertext => $encrypted,
        identities => [$secret],
    );

    # Encrypt file
    Crypt::Age->encrypt_file(
        input      => 'secret.txt',
        output     => 'secret.txt.age',
        recipients => [$public],
    );

    # Decrypt file
    Crypt::Age->decrypt_file(
        input      => 'secret.txt.age',
        output     => 'secret.txt',
        identities => [$secret],
    );

=head1 DESCRIPTION

Crypt::Age is a pure Perl implementation of the age encryption format,
compatible with the reference Go implementation (L<https://github.com/FiloSottile/age>)
and the Rust implementation (L<https://github.com/str4d/rage>).

age is a simple, modern and secure file encryption tool with small explicit
keys, no config options, and UNIX-style composability. The format specification
is available at L<https://github.com/C2SP/C2SP/blob/main/age.md>.

This implementation uses X25519 for key exchange, ChaCha20-Poly1305 for
authenticated encryption, and HKDF-SHA256 for key derivation. All cryptographic
primitives are provided by L<CryptX>.

Files encrypted with Crypt::Age can be decrypted with the C<age> and C<rage>
command-line tools, and vice versa.

Two APIs are provided, and they differ in memory use. L</encrypt> and
L</decrypt> take and return in-memory strings, so the whole plaintext or
ciphertext has to fit in memory at once, both as the argument and as the
returned value. L</encrypt_file>, L</decrypt_file>, L</encrypt_filehandle> and
L</decrypt_filehandle> stream instead: they read and write in 64 KiB chunks, so
memory use stays bounded regardless of how large the file is.

See L</LIMITATIONS> below for what this module does not implement.

=cut

our $VERSION = '0.003';

sub generate_keypair {
    my ($class) = @_;
    return Crypt::Age::Keys->generate_keypair;
}

=method generate_keypair

    my ($public_key, $secret_key) = Crypt::Age->generate_keypair();

Generates a new X25519 keypair for age encryption.

Returns a list of two elements:

=over 4

=item * C<$public_key> - Bech32-encoded public key starting with C<age1>

=item * C<$secret_key> - Bech32-encoded secret key starting with C<AGE-SECRET-KEY-1>

=back

The public key can be shared with others to encrypt files for you. The secret
key must be kept private and is used to decrypt files encrypted to your public key.

=cut

sub encrypt {
    my ($class, %args) = @_;

    my $plaintext  = $args{plaintext}  // croak "plaintext required";
    my $recipients = $args{recipients} // croak "recipients required";

    open my $ifh, '<:raw', \$plaintext or die "open on input string: $!";

    my $output = '';
    open my $ofh, '>:raw', \$output or die "open on output string: $!";

    $class->_encrypt_fh($ifh, $ofh, $recipients);

    return $output;
}

=method encrypt

    my $ciphertext = Crypt::Age->encrypt(
        plaintext  => $data,
        recipients => \@public_keys,
    );

Encrypts plaintext data for one or more recipients.

Parameters:

=over 4

=item * C<plaintext> - The data to encrypt (required)

=item * C<recipients> - ArrayRef of Bech32-encoded public keys (required)

=back

Returns the encrypted data in age format, which includes a text header followed
by the encrypted payload. The file key is wrapped separately for each recipient,
allowing any of them to decrypt the data.

The returned data can be written to a file or transmitted directly.

C<plaintext> and the returned ciphertext are both held in memory in full. For
large data, use L</encrypt_file> or L</encrypt_filehandle>, which stream in 64
KiB chunks instead.

=cut

sub decrypt {
    my ($class, %args) = @_;

    my $ciphertext = $args{ciphertext} // croak "ciphertext required";
    my $identities = $args{identities} // croak "identities required";

    open my $ifh, '<:raw', \$ciphertext or die "open on input string: $!";

    my $output = '';
    open my $ofh, '>:raw', \$output or die "open on output string: $!";

    $class->_decrypt_fh($ifh, $ofh, $identities);

    return $output;
}

=method decrypt

    my $plaintext = Crypt::Age->decrypt(
        ciphertext => $encrypted,
        identities => \@secret_keys,
    );

Decrypts age-encrypted data using one or more identities.

Parameters:

=over 4

=item * C<ciphertext> - The age-encrypted data (required)

=item * C<identities> - ArrayRef of Bech32-encoded secret keys (required)

=back

Returns the decrypted plaintext.

The method tries each identity against each recipient stanza in the header until
one successfully unwraps the file key. Dies if no matching identity is found or
if the MAC verification fails.

C<ciphertext> and the returned plaintext are both held in memory in full. For
large data, use L</decrypt_file> or L</decrypt_filehandle>, which stream in 64
KiB chunks instead. Because this method never returns a value on failure, a
decryption that dies here does not expose any partial plaintext to the caller
-- contrast L</decrypt_filehandle>, which writes to a caller-supplied handle
and so can leave an authenticated-but-incomplete prefix behind.

=cut

sub _encrypt_fh {
    my ($class, $ifh, $ofh, $recipients) = @_;
    binmode($ifh, ':raw') or croak "cannot binmode input filehandle: $!";
    binmode($ofh, ':raw') or croak "cannot binmode output filehandle: $!";

    croak "recipients must be an array ref" unless ref($recipients) eq 'ARRAY';
    croak "at least one recipient required" unless @$recipients;

    # Generate random file key
    my $file_key = Crypt::Age::Primitives->generate_file_key;

    # Create header with wrapped file key for each recipient
    print {$ofh} Crypt::Age::Header->create($file_key, $recipients)->to_string;

    # Generate payload nonce and derive payload key
    my $nonce = Crypt::Age::Primitives->generate_payload_nonce;
    print {$ofh} $nonce;

    my $payload_key = Crypt::Age::Primitives->derive_payload_key($file_key, $nonce);
    return Crypt::Age::Primitives->encrypt_payload_fh($payload_key, $ifh, $ofh);
}

sub encrypt_file {
    my ($class, %args) = @_;
    my $input      = $args{input}      // croak "input required";
    my $output     = $args{output}     // croak "output required";
    my $recipients = $args{recipients} // croak "recipients required";

    open my $in_fh, '<:raw', $input
        or croak "Cannot open input file '$input': $!";
    open my $out_fh, '>:raw', $output
        or croak "Cannot open output file '$output': $!";

    $class->_encrypt_fh($in_fh, $out_fh, $recipients);

    close $out_fh or croak "Cannot close output file '$output': $!";
    close $in_fh  or croak "Cannot close input file '$input': $!";

    return 1;
}

=method encrypt_file

    Crypt::Age->encrypt_file(
        input      => 'plaintext.txt',
        output     => 'encrypted.age',
        recipients => \@public_keys,
    );

Encrypts a file for one or more recipients.

Parameters:

=over 4

=item * C<input> - Path to input file (required)

=item * C<output> - Path to output file (required)

=item * C<recipients> - ArrayRef of Bech32-encoded public keys (required)

=back

The output file will be in age format and can be decrypted with the C<age> or
C<rage> command-line tools.

Returns C<1> on success. Dies on error (file not found, permission denied, etc).
Reads and writes the file in 64 KiB chunks, so memory use does not grow with
the size of the file.

=cut

sub encrypt_filehandle {
    my ($class, %args) = @_;
    my $in_fh      = $args{input}      // croak "input required";
    my $out_fh     = $args{output}     // croak "output required";
    my $recipients = $args{recipients} // croak "recipients required";

    $class->_encrypt_fh($in_fh, $out_fh, $recipients);

    return 1;

}

=method encrypt_filehandle

    Crypt::Age->encrypt_filehandle(
        input      => \*STDIN,
        output     => \*STDOUT,
        recipients => \@public_keys,
    );

Encrypts for one or more recipients, based on filehandles for both input and
output.

Parameters:

=over 4

=item * C<input> - Input filehandle (required)

=item * C<output> - Output filehandle (required)

=item * C<recipients> - ArrayRef of Bech32-encoded public keys (required)

=back

Both filehandles will be forced to be C<:raw> using C<binmode>.

The output stream will be in age format and can be decrypted with the C<age> or
C<rage> command-line tools.

Returns C<1> on success. Dies if a required argument is missing, if
C<recipients> is not a non-empty array ref, if a recipient string is not a
valid Bech32 C<age1...> public key, or if C<binmode> fails on either handle.
Unlike L</encrypt_file>, this method never opens or closes a file itself --
C<input> and C<output> are handles the caller already has open -- so it cannot
die with a "file not found" or "permission denied" error; that is the
caller's concern before the handle is passed in. Streams in 64 KiB chunks, so
memory use does not grow with the amount of data written.

=cut

sub _decrypt_fh {
    my ($class, $ifh, $ofh, $identities) = @_;
    binmode($ifh, ':raw') or croak "cannot binmode input filehandle: $!";
    binmode($ofh, ':raw') or croak "cannot binmode output filehandle: $!";

    croak "identities must be an array ref" unless ref($identities) eq 'ARRAY';
    croak "at least one identity required" unless @$identities;

    # Parse header
    my $header = Crypt::Age::Header->parse_from_fh($ifh);

    # Unwrap file key using identities
    my $file_key = $header->unwrap_file_key($identities);

    # Extract nonce (first 16 bytes after header) and encrypted payload
    my $nonce = Crypt::Age::Primitives->paranoid_read($ifh, 16);
    croak 'end of file reached before getting nonce' if length($nonce) != 16;

    # Derive payload key using nonce
    my $payload_key = Crypt::Age::Primitives->derive_payload_key($file_key, $nonce);

    return Crypt::Age::Primitives->decrypt_payload_fh($payload_key, $ifh, $ofh);
}

sub decrypt_file {
    my ($class, %args) = @_;
    my $input      = $args{input}      // croak "input required";
    my $output     = $args{output}     // croak "output required";
    my $identities = $args{identities} // croak "identities required";

    open my $in_fh, '<:raw', $input
        or croak "Cannot open input file '$input': $!";
    open my $out_fh, '>:raw', $output
        or croak "Cannot open output file '$output': $!";

    $class->_decrypt_fh($in_fh, $out_fh, $identities);

    close $out_fh or croak "Cannot close output file '$output': $!";
    close $in_fh  or croak "Cannot close input file '$input': $!";

    return 1;
}

=method decrypt_file

    Crypt::Age->decrypt_file(
        input      => 'encrypted.age',
        output     => 'plaintext.txt',
        identities => \@secret_keys,
    );

Decrypts an age-encrypted file using one or more identities.

Parameters:

=over 4

=item * C<input> - Path to encrypted input file (required)

=item * C<output> - Path to decrypted output file (required)

=item * C<identities> - ArrayRef of Bech32-encoded secret keys (required)

=back

Returns C<1> on success. Dies if the header is invalid, if no identity matches
any stanza, if the MAC verification fails, if payload authentication fails, or
on file I/O errors.

Reads the input and writes the output in 64 KiB chunks, so memory use does not
grow with the size of the file. B<This means a failure does not undo what was
already written>: every chunk that authenticated before the error is already
in C<output> on disk once this method dies. Each such chunk is individually
authentic, but the file as a whole is not -- that is exactly what the error
reports. Treat a partial C<output> as undecrypted and discard it; do not rely
on the bytes that made it out. See L<Crypt::Age::Primitives/decrypt_payload_fh>
for the same guarantee stated at the primitive layer.

=cut

sub decrypt_filehandle {
    my ($class, %args) = @_;
    my $in_fh      = $args{input}      // croak "input required";
    my $out_fh     = $args{output}     // croak "output required";
    my $identities = $args{identities} // croak "identities required";

    $class->_decrypt_fh($in_fh, $out_fh, $identities);

    return 1;
}

=method decrypt_filehandle

    Crypt::Age->decrypt_filehandle(
        input      => \*STDIN,
        output     => \*STDOUT,
        identities => \@secret_keys,
    );

Decrypts age-encrypted data from a filehandle using one or more identities.
Output is sent to a filehandle too.

Parameters:

=over 4

=item * C<input> - Encrypted input filehandle (required)

=item * C<output> - Decrypted output filehandle (required)

=item * C<identities> - ArrayRef of Bech32-encoded secret keys (required)

=back

Both filehandles will be forced to be C<:raw> using C<binmode>.

Returns C<1> on success. Dies if a required argument is missing, if the header
is invalid, if no identity matches any stanza, if the MAC verification fails,
if payload authentication fails, or if C<binmode> fails on either handle.
Unlike L</decrypt_file>, this method never opens or closes a file itself --
C<input> and C<output> are handles the caller already has open -- so it cannot
die with a "file not found" or "permission denied" error; that is the
caller's concern before the handle is passed in.

Decryption streams: plaintext is written to C<output> one 64 KiB chunk at a
time as each chunk authenticates, so memory use does not grow with the amount
of data decrypted. B<This also means a failure does not undo what was already
written.> If the payload is truncated or corrupt, every chunk that
authenticated before the error is already in C<output> when this method dies;
each of those chunks is individually authentic, but the message as a whole is
not, which is exactly what the error reports. A caller must treat whatever
reached C<output> as unauthenticated and discard it, rather than as a decrypted
message merely because its individual bytes checked out. See
L<Crypt::Age::Primitives/decrypt_payload_fh> for the same guarantee stated at
the primitive layer.

=cut

=head1 KEY FORMAT

=head2 Public Keys

Public keys are Bech32-encoded X25519 public keys with the human-readable
part C<age>:

    age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

=head2 Secret Keys

Secret keys are uppercase Bech32-encoded X25519 secret keys with the
human-readable part C<AGE-SECRET-KEY->:

    AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ8H00W3

=head1 INTEROPERABILITY

This module is designed to be compatible with:

=over 4

=item * L<https://github.com/FiloSottile/age> - Reference Go implementation

=item * L<https://github.com/str4d/rage> - Rust implementation

=back

Files encrypted with Crypt::Age can be decrypted with these tools and vice versa.

=head1 LIMITATIONS

Only the C<X25519> recipient type is implemented, and it is complete in both
directions: keypair generation, header creation and parsing, wrapping and
unwrapping, and the header MAC. Not implemented:

=over 4

=item * scrypt (passphrase) recipients

=item * SSH recipients

=item * the post-quantum and tagged recipient types (C<mlkem768x25519> and
similar)

=item * ASCII armor

=back

A stanza of one of these types is not rejected outright: the format requires
unrecognized stanza types to be ignored, and this implementation does that (see
L<Crypt::Age::Header/parse_from_fh>), so a file with both an C<X25519>
recipient and, say, a C<scrypt> one still decrypts normally for an identity
that matches the C<X25519> stanza. But a file whose recipients are all of
these unsupported types dies: L</decrypt> and the other decrypt methods raise
C<"No matching identity found">, since L<Crypt::Age::Header/unwrap_file_key>
only tries stanzas it recognizes as C<X25519>. An armored file fails even
earlier, because its first line is not the literal C<age-encryption.org/v1>
version line that L<Crypt::Age::Header/parse_from_fh> requires. On the encrypt
side, passing a recipient string that is not a Bech32 C<age1...> public key
dies with C<"Unsupported recipient format">.

=head1 SECURITY

age uses modern cryptographic primitives:

=over 4

=item * X25519 for key agreement (Curve25519 Diffie-Hellman)

=item * ChaCha20-Poly1305 for authenticated encryption

=item * HKDF-SHA256 for key derivation

=back

The file key is randomly generated for each encryption operation. The payload
is encrypted in 64 KiB chunks with unique nonces derived from a counter and
final-chunk flag.

=head1 SEE ALSO

=over 4

=item * L<https://age-encryption.org> - age encryption homepage

=item * L<https://github.com/C2SP/C2SP/blob/main/age.md> - age format specification

=item * L<CryptX> - Cryptographic toolkit providing all primitives

=item * L<Crypt::Age::Header> - Header parsing, generation and the header MAC

=item * L<Crypt::Age::Stanza> - Base recipient stanza class

=item * L<Crypt::Age::Stanza::X25519> - X25519 recipient stanza

=item * L<Crypt::Age::Keys> - Key generation and encoding

=item * L<Crypt::Age::Primitives> - Low-level cryptographic operations

=back

=cut

1;
