package Crypt::Age::Primitives;
# ABSTRACT: Low-level cryptographic primitives for age encryption

use Moo;
use Carp qw(croak);
use Crypt::PK::X25519;
use Crypt::AuthEnc::ChaCha20Poly1305;
use Crypt::KeyDerivation qw(hkdf);
use Crypt::Mac::HMAC qw(hmac);
use Crypt::PRNG qw(random_bytes);
use namespace::clean;

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

sub x25519_generate_keypair {
    my ($class) = @_;
    my $pk = Crypt::PK::X25519->new;
    $pk->generate_key;
    return ($pk->export_key_raw('public'), $pk->export_key_raw('private'));
}

sub x25519_shared_secret {
    my ($class, $our_private, $their_public) = @_;

    my $our_pk = Crypt::PK::X25519->new;
    $our_pk->import_key_raw($our_private, 'private');

    my $their_pk = Crypt::PK::X25519->new;
    $their_pk->import_key_raw($their_public, 'public');

    return $our_pk->shared_secret($their_pk);
}

sub derive_wrap_key {
    my ($class, $shared_secret, $ephemeral_public, $recipient_public) = @_;

    # salt = ephemeral_public || recipient_public
    my $salt = $ephemeral_public . $recipient_public;

    # hkdf($secret, $salt, $hash, $length, $info)
    return hkdf($shared_secret, $salt, 'SHA256', 32, LABEL_X25519);
}

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

sub derive_payload_key {
    my ($class, $file_key) = @_;

    # Derive payload key using HKDF
    # hkdf($secret, $salt, $hash, $length, $info)
    return hkdf($file_key, '', 'SHA256', 32, LABEL_PAYLOAD);
}

sub compute_header_mac {
    my ($class, $file_key, $header_bytes) = @_;

    # Derive MAC key using HKDF
    # hkdf($secret, $salt, $hash, $length, $info)
    my $mac_key = hkdf($file_key, '', 'SHA256', 32, LABEL_HEADER);

    return hmac('SHA256', $mac_key, $header_bytes);
}

sub encrypt_payload {
    my ($class, $payload_key, $plaintext) = @_;

    my @chunks;
    my $offset = 0;
    my $counter = 0;
    my $remaining = length($plaintext);

    while ($remaining > 0 || $counter == 0) {
        my $chunk_size = $remaining > CHUNK_SIZE ? CHUNK_SIZE : $remaining;
        my $chunk = substr($plaintext, $offset, $chunk_size);
        my $is_final = ($remaining <= CHUNK_SIZE);

        my $nonce = $class->_make_nonce($counter, $is_final);
        my $ae = Crypt::AuthEnc::ChaCha20Poly1305->new($payload_key, $nonce);

        my $ciphertext = $ae->encrypt_add($chunk);
        my $tag = $ae->encrypt_done;

        push @chunks, $ciphertext . $tag;

        $offset += $chunk_size;
        $remaining -= $chunk_size;
        $counter++;

        last if $is_final;
    }

    return join('', @chunks);
}

sub decrypt_payload {
    my ($class, $payload_key, $ciphertext) = @_;

    my @plaintext_chunks;
    my $offset = 0;
    my $counter = 0;
    my $remaining = length($ciphertext);

    while ($remaining > 0) {
        # Each encrypted chunk is plaintext + 16 byte tag
        my $max_encrypted_chunk = CHUNK_SIZE + TAG_SIZE;
        my $chunk_size = $remaining > $max_encrypted_chunk ? $max_encrypted_chunk : $remaining;

        my $encrypted_chunk = substr($ciphertext, $offset, $chunk_size);
        my $is_final = ($remaining <= $max_encrypted_chunk);

        my $ct = substr($encrypted_chunk, 0, -TAG_SIZE);
        my $tag = substr($encrypted_chunk, -TAG_SIZE);

        my $nonce = $class->_make_nonce($counter, $is_final);
        my $ae = Crypt::AuthEnc::ChaCha20Poly1305->new($payload_key, $nonce);

        my $plaintext = $ae->decrypt_add($ct);
        croak "Payload authentication failed at chunk $counter"
            unless $ae->decrypt_done($tag);

        push @plaintext_chunks, $plaintext;

        $offset += $chunk_size;
        $remaining -= $chunk_size;
        $counter++;
    }

    return join('', @plaintext_chunks);
}

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

1;
