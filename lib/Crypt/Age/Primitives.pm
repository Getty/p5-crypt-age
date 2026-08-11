package Crypt::Age::Primitives;
# ABSTRACT: Low-level cryptographic primitives for age encryption
our $VERSION = '0.002';
use Moo;
use Carp qw(croak);
use Crypt::PK::X25519;
use Crypt::AuthEnc::ChaCha20Poly1305;
use Crypt::KeyDerivation qw(hkdf);
use Crypt::Mac::HMAC qw(hmac);
use Crypt::PRNG qw(random_bytes);

use constant READ_ATTEMPTS => 3;

use namespace::clean;

=head1 SYNOPSIS

    use Crypt::Age::Primitives;

    # Generate random file key
    my $file_key = Crypt::Age::Primitives->generate_file_key();

    # X25519 key exchange
    my ($pub, $priv) = Crypt::Age::Primitives->x25519_generate_keypair();
    my $secret = Crypt::Age::Primitives->x25519_shared_secret($our_priv, $their_pub);

    # Key derivation and wrapping
    my $wrap_key = Crypt::Age::Primitives->derive_wrap_key($secret, $eph_pub, $rec_pub);
    my $wrapped = Crypt::Age::Primitives->wrap_file_key($wrap_key, $file_key);
    my $unwrapped = Crypt::Age::Primitives->unwrap_file_key($wrap_key, $wrapped);

    # Payload encryption
    my $payload_key = Crypt::Age::Primitives->derive_payload_key($file_key);
    my $encrypted = Crypt::Age::Primitives->encrypt_payload($payload_key, $plaintext);
    my $decrypted = Crypt::Age::Primitives->decrypt_payload($payload_key, $encrypted);

    # Header MAC
    my $mac = Crypt::Age::Primitives->compute_header_mac($file_key, $header_bytes);

=head1 DESCRIPTION

This module provides low-level cryptographic primitives for age encryption.
It wraps functions from L<CryptX> and implements the age-specific key
derivation and payload encryption schemes.

This is an internal module used by L<Crypt::Age>. Most users should use the
high-level interface provided by L<Crypt::Age> instead.

=head2 Cryptographic Primitives Used

=over 4

=item * X25519 - Key exchange (Curve25519 Diffie-Hellman)

=item * ChaCha20-Poly1305 - AEAD encryption

=item * HKDF-SHA256 - Key derivation

=item * HMAC-SHA256 - Header MAC

=back

=cut

# Constants from age spec
use constant {
    FILE_KEY_SIZE    => 16,
    X25519_KEY_SIZE  => 32,
    CHUNK_SIZE       => 64 * 1024,  # 64 KiB
    NONCE_SIZE       => 12,
    TAG_SIZE         => 16,
};

# HKDF labels from age spec
use constant {
    LABEL_X25519     => "age-encryption.org/v1/X25519",
    LABEL_HEADER     => "header",
    LABEL_PAYLOAD    => "payload",
};

sub generate_file_key {
    return random_bytes(FILE_KEY_SIZE);
}

=method generate_file_key

    my $file_key = Crypt::Age::Primitives->generate_file_key();

Generates a random 16-byte file key using a cryptographically secure PRNG.

The file key is used to encrypt the payload and is itself encrypted for each
recipient.

=cut

sub x25519_generate_keypair {
    my ($class) = @_;
    my $pk = Crypt::PK::X25519->new;
    $pk->generate_key;
    return ($pk->export_key_raw('public'), $pk->export_key_raw('private'));
}

=method x25519_generate_keypair

    my ($public_bytes, $private_bytes) = Crypt::Age::Primitives->x25519_generate_keypair();

Generates a new X25519 keypair. Returns raw 32-byte public and private keys.

Note: For generating age-encoded keypairs, use L<Crypt::Age::Keys/generate_keypair>
instead.

=cut

sub x25519_shared_secret {
    my ($class, $our_private, $their_public) = @_;

    my $our_pk = Crypt::PK::X25519->new;
    $our_pk->import_key_raw($our_private, 'private');

    my $their_pk = Crypt::PK::X25519->new;
    $their_pk->import_key_raw($their_public, 'public');

    return $our_pk->shared_secret($their_pk);
}

=method x25519_shared_secret

    my $shared_secret = Crypt::Age::Primitives->x25519_shared_secret($our_private, $their_public);

Performs X25519 key exchange to compute a shared secret.

Parameters are raw 32-byte keys. Returns a 32-byte shared secret.

=cut

sub derive_wrap_key {
    my ($class, $shared_secret, $ephemeral_public, $recipient_public) = @_;

    # salt = ephemeral_public || recipient_public
    my $salt = $ephemeral_public . $recipient_public;

    # hkdf($secret, $salt, $hash, $length, $info)
    return hkdf($shared_secret, $salt, 'SHA256', 32, LABEL_X25519);
}

=method derive_wrap_key

    my $wrap_key = Crypt::Age::Primitives->derive_wrap_key(
        $shared_secret,
        $ephemeral_public,
        $recipient_public
    );

Derives a wrapping key from an X25519 shared secret using HKDF-SHA256.

The salt is C<ephemeral_public || recipient_public> (concatenated).
The info string is C<"age-encryption.org/v1/X25519">.

Returns a 32-byte key suitable for wrapping the file key.

=cut

sub wrap_file_key {
    my ($class, $wrap_key, $file_key) = @_;

    croak "Wrap key must be 32 bytes" unless length($wrap_key) == 32;
    croak "File key must be 16 bytes" unless length($file_key) == FILE_KEY_SIZE;

    # ChaCha20-Poly1305 with zero nonce
    my $nonce = "\x00" x NONCE_SIZE;
    my $ae = Crypt::AuthEnc::ChaCha20Poly1305->new($wrap_key, $nonce);
    my $ciphertext = $ae->encrypt_add($file_key);
    my $tag = $ae->encrypt_done;

    return $ciphertext . $tag;
}

=method wrap_file_key

    my $wrapped_key = Crypt::Age::Primitives->wrap_file_key($wrap_key, $file_key);

Wraps a 16-byte file key using ChaCha20-Poly1305 with a zero nonce.

Returns a 32-byte value: 16 bytes ciphertext + 16 bytes authentication tag.

=cut

sub unwrap_file_key {
    my ($class, $wrap_key, $wrapped_key) = @_;

    croak "Wrap key must be 32 bytes" unless length($wrap_key) == 32;
    croak "Wrapped key must be 32 bytes" unless length($wrapped_key) == FILE_KEY_SIZE + TAG_SIZE;

    my $ciphertext = substr($wrapped_key, 0, FILE_KEY_SIZE);
    my $tag = substr($wrapped_key, FILE_KEY_SIZE, TAG_SIZE);

    my $nonce = "\x00" x NONCE_SIZE;
    my $ae = Crypt::AuthEnc::ChaCha20Poly1305->new($wrap_key, $nonce);
    my $file_key = $ae->decrypt_add($ciphertext);

    croak "Authentication failed" unless $ae->decrypt_done($tag);

    return $file_key;
}

=method unwrap_file_key

    my $file_key = Crypt::Age::Primitives->unwrap_file_key($wrap_key, $wrapped_key);

Unwraps a wrapped file key using ChaCha20-Poly1305.

Dies if authentication fails. Returns the 16-byte file key on success.

=cut

sub derive_payload_key {
    my ($class, $file_key, $nonce) = @_;

    croak "nonce required" unless defined $nonce;
    croak "nonce must be 16 bytes" unless length($nonce) == 16;

    # Derive payload key using HKDF
    # hkdf($secret, $salt, $hash, $length, $info)
    # The nonce is used as salt, and "payload" is the info string
    return hkdf($file_key, $nonce, 'SHA256', 32, LABEL_PAYLOAD);
}

sub generate_payload_nonce {
    return random_bytes(16);
}

=method derive_payload_key

    my $payload_key = Crypt::Age::Primitives->derive_payload_key($file_key, $nonce);

Derives a 32-byte payload encryption key from the file key and nonce using HKDF-SHA256.

The nonce (16 bytes) is used as the salt, and C<"payload"> is the info string.

=method generate_payload_nonce

    my $nonce = Crypt::Age::Primitives->generate_payload_nonce();

Generates a random 16-byte nonce for payload encryption.

=cut

sub compute_header_mac {
    my ($class, $file_key, $header_bytes) = @_;

    # Derive MAC key using HKDF
    # hkdf($secret, $salt, $hash, $length, $info)
    my $mac_key = hkdf($file_key, '', 'SHA256', 32, LABEL_HEADER);

    return hmac('SHA256', $mac_key, $header_bytes);
}

=method compute_header_mac

    my $mac = Crypt::Age::Primitives->compute_header_mac($file_key, $header_bytes);

Computes HMAC-SHA256 MAC over the header bytes.

First derives a MAC key from the file key using HKDF with info string C<"header">,
then computes HMAC-SHA256 of the header. Returns 32 bytes.

=cut

sub encrypt_payload {
    my ($class, $payload_key, $plaintext) = @_;

    open my $ifh, '<:raw', \$plaintext or croak "Cannot open input string: $!";

    my $output = '';
    open my $ofh, '>:raw', \$output or croak "Cannot open output string: $!";

    $class->encrypt_payload_fh($payload_key, $ifh, $ofh);

    close $ofh or croak "Cannot close output string: $!";
    close $ifh  or croak "Cannot close input string: $!";

    return $output;
}

=method encrypt_payload

    my $ciphertext = Crypt::Age::Primitives->encrypt_payload($payload_key, $plaintext);

Encrypts the payload using ChaCha20-Poly1305 in chunked mode.

The plaintext is split into 64 KiB chunks. Each chunk is encrypted with a unique
nonce derived from a counter and a final-chunk flag. Returns the concatenated
encrypted chunks.

=cut

sub encrypt_payload_fh {
    my ($class, $payload_key, $ifh, $ofh) = @_;

    my $counter = 0;
    my $is_final = 0;
    while (! $is_final) {
        my $chunk = $class->paranoid_read($ifh, CHUNK_SIZE);
        $is_final = eof($ifh);

        my $nonce = $class->_make_nonce($counter, $is_final);
        my $ae = Crypt::AuthEnc::ChaCha20Poly1305->new($payload_key, $nonce);

        my $ciphertext = $ae->encrypt_add($chunk);
        my $tag = $ae->encrypt_done;

        print {$ofh} $ciphertext, $tag;

        $counter++;
    }

    return;
}

=method encrypt_payload_fh

    my $ciphertext = Crypt::Age::Primitives->encrypt_payload_fh($payload_key, $ifh, $ofh);

Encrypts the payload using ChaCha20-Poly1305 in chunked mode, using filehandles
for both input and output.

The plaintext is split into 64 KiB chunks. Each chunk is encrypted with a unique
nonce derived from a counter and a final-chunk flag. Returns the concatenated
encrypted chunks.

=cut

sub decrypt_payload {
    my ($class, $payload_key, $ciphertext) = @_;

    open my $ifh, '<:raw', \$ciphertext or croak "Cannot open input string: $!";

    my $output = '';
    open my $ofh, '>:raw', \$output or croak "Cannot open output string: $!";

    $class->decrypt_payload_fh($payload_key, $ifh, $ofh);

    close $ofh or croak "Cannot close output string: $!";
    close $ifh  or croak "Cannot close input string: $!";

    return $output;
}

=method decrypt_payload

    my $plaintext = Crypt::Age::Primitives->decrypt_payload($payload_key, $ciphertext);

Decrypts a chunked payload encrypted with C<encrypt_payload>.

Dies if any chunk fails authentication. Returns the decrypted plaintext.

=cut

sub decrypt_payload_fh {
    my ($class, $payload_key, $ifh, $ofh) = @_;

    my $max_encrypted_chunk = CHUNK_SIZE + TAG_SIZE;
    my $counter = 0;
    my $is_final = 0;
    while (! $is_final) {
        # Each encrypted chunk is plaintext + 16 byte tag
        my $ct = $class->paranoid_read($ifh, $max_encrypted_chunk);
        my $tag = substr($ct, -TAG_SIZE, TAG_SIZE, '');

        $is_final = eof($ifh);
        my $nonce = $class->_make_nonce($counter, $is_final);
        my $ae = Crypt::AuthEnc::ChaCha20Poly1305->new($payload_key, $nonce);

        my $plaintext = $ae->decrypt_add($ct);
        croak "Payload authentication failed at chunk $counter"
            unless $ae->decrypt_done($tag);

        print {$ofh} $plaintext;

        $counter++;
    }

    return;
}

=method decrypt_payload_fh

    my $plaintext = Crypt::Age::Primitives->decrypt_payload_fh($payload_key, $ifh, $ofh);

Decrypts a chunked payload encrypted with C<encrypt_payload>, using filehandles
for both input and output.

Dies if any chunk fails authentication.

=cut

sub _make_nonce {
    my ($class, $counter, $is_final) = @_;

    # 11 bytes counter (big-endian) + 1 byte final flag
    my $nonce = pack('x3 N N', ($counter >> 32) & 0xFFFFFFFF, $counter & 0xFFFFFFFF);
    # Actually, the nonce is: 11-byte big-endian counter || 1-byte last-block flag
    # Let's be more precise:
    $nonce = "\x00" x 3;  # First 3 bytes zero
    $nonce .= pack('N', ($counter >> 32) & 0xFFFFFFFF);  # Next 4 bytes
    $nonce .= pack('N', $counter & 0xFFFFFFFF);          # Next 4 bytes
    $nonce .= pack('C', $is_final ? 1 : 0);              # Last byte: final flag

    return $nonce;
}

sub paranoid_read {
    my ($class, $fh, $length) = @_;
    my $retval = '';
    my $attempts = READ_ATTEMPTS;
    while ($length > 0 && $attempts > 0) {
        my $buffer = '';
        my $n_read = read($fh, $buffer, $length);
        croak "read(): $!" if ! defined($n_read);
        if ($n_read == 0) {
            last if eof($fh); # no more data, we're good
            --$attempts;
            next;
        }

        # reset attempts after successful read of *some* data
        $attempts = READ_ATTEMPTS;
        $retval .= $buffer;
        $length -= $n_read;
    }
    return $retval if $attempts > 0;
    croak "could not get requested data up to the end";
}

=head1 SEE ALSO

=over 4

=item * L<Crypt::Age> - Main age encryption module

=item * L<CryptX> - Provides all cryptographic primitives

=item * L<Crypt::PK::X25519> - X25519 key exchange

=item * L<Crypt::AuthEnc::ChaCha20Poly1305> - AEAD encryption

=item * L<Crypt::KeyDerivation> - HKDF implementation

=back

=cut

1;
