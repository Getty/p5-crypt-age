package Crypt::Age::Stanza::X25519;
# ABSTRACT: X25519 recipient stanza for age encryption

use Moo;
use Carp qw(croak);
use Crypt::Age::Keys;
use Crypt::Age::Primitives;
use Crypt::Age::Stanza;
use namespace::clean;

extends 'Crypt::Age::Stanza';

has '+type' => (
    default => 'X25519',
);

has ephemeral_public => (
    is => 'ro',
);

sub wrap {
    my ($class, $file_key, $recipient_public_key) = @_;

    # Decode recipient public key (Bech32 -> raw bytes)
    my $recipient_public = Crypt::Age::Keys->decode_public_key($recipient_public_key);

    # Generate ephemeral keypair
    my ($ephemeral_public, $ephemeral_private) =
        Crypt::Age::Primitives->x25519_generate_keypair;

    # Compute shared secret
    my $shared_secret = Crypt::Age::Primitives->x25519_shared_secret(
        $ephemeral_private,
        $recipient_public
    );

    # Derive wrap key
    my $wrap_key = Crypt::Age::Primitives->derive_wrap_key(
        $shared_secret,
        $ephemeral_public,
        $recipient_public
    );

    # Wrap file key
    my $wrapped_key = Crypt::Age::Primitives->wrap_file_key($wrap_key, $file_key);

    # Create stanza
    return $class->new(
        args             => [Crypt::Age::Stanza::encode_base64_no_padding($ephemeral_public)],
        body             => $wrapped_key,
        ephemeral_public => $ephemeral_public,
    );
}

sub unwrap {
    my ($self, $identity_secret_key) = @_;

    # Decode identity secret key (Bech32 -> raw bytes)
    my $identity_private = Crypt::Age::Keys->decode_secret_key($identity_secret_key);

    # Get recipient's public key from identity
    my $pk = Crypt::PK::X25519->new;
    $pk->import_key_raw($identity_private, 'private');
    my $recipient_public = $pk->export_key_raw('public');

    # Decode ephemeral public key from stanza args
    my $ephemeral_public = Crypt::Age::Stanza::decode_base64_no_padding($self->args->[0]);

    # Compute shared secret
    my $shared_secret = Crypt::Age::Primitives->x25519_shared_secret(
        $identity_private,
        $ephemeral_public
    );

    # Derive wrap key
    my $wrap_key = Crypt::Age::Primitives->derive_wrap_key(
        $shared_secret,
        $ephemeral_public,
        $recipient_public
    );

    # Unwrap file key
    my $file_key = eval {
        Crypt::Age::Primitives->unwrap_file_key($wrap_key, $self->body);
    };

    return $file_key;  # Returns undef if unwrap failed
}

1;
