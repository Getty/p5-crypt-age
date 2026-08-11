package Crypt::Age::Stanza::Scrypt;
# ABSTRACT: X25519 recipient stanza for age encryption
our $VERSION = '0.002';
use Moo;
use Carp qw(croak);
use Crypt::Age::Keys;
use Crypt::Age::Primitives;
use Crypt::Age::Stanza;
use Crypt::PRNG qw(random_bytes);
use Crypt::KeyDerivation qw(scrypt_pbkdf);

use constant MAX_WORK_FACTOR        => 32; # just a guess...
use constant DEFAULT_WORK_FACTOR    => 18; # just a guess...
use constant DEFAULT_BLOCK_SIZE     => 8;
use constant DEFAULT_PARALLELIZATON => 1;
use constant DEFAULT_KEY_LENGTH     => 32;
use constant DEFAULT_SALT_PREFIX    => 'age-encryption.org/v1/scrypt';

use namespace::clean;

=head1 SYNOPSIS

    use Crypt::Age::Stanza::X25519;

    # Create stanza by wrapping file key for a recipient
    my $stanza = Crypt::Age::Stanza::X25519->wrap($file_key, $recipient_public_key);

    # Unwrap file key using identity
    my $file_key = $stanza->unwrap($identity_secret_key);

=head1 DESCRIPTION

This module implements X25519 recipient stanzas for age encryption.

X25519 stanzas use Curve25519 Diffie-Hellman key exchange to derive a shared
secret, which is then used to wrap the file key with ChaCha20-Poly1305.

The stanza format is:

    -> X25519 <base64-ephemeral-public-key>
    <base64-wrapped-file-key>

The ephemeral public key is generated randomly for each encryption operation.
The recipient uses their identity (secret key) to compute the same shared
secret and unwrap the file key.

This is the primary recipient type for age encryption.

=cut

extends 'Crypt::Age::Stanza';

sub type { return 'scrypt' }

# scrypt does not have a HRP so we unconditionally declare our ability
# to do wrap and unwrap
#sub identity_hrp { return 'AGE-SECRET-KEY-' }
#sub recipient_hrp { return 'age' }
sub can_wrap   { return 1 }
sub can_unwrap { return 1 }

sub args {
    my $self = shift;
    my $salt = $self->salt;
    my $wf = $self->work_factor;
    return [ Crypt::Age::Stanza::encode_base64_no_padding($salt), $wf ];
}

has salt => (
    is => 'ro',
);

has work_factor => (
    is => 'ro',
);


=attr ephemeral_public

The ephemeral X25519 public key used for this stanza (raw bytes).

Generated randomly during wrapping.

=cut

around BUILDARGS => sub {
    my ($orig, $class, @build_args) = @_;
    my %for_self = @build_args == 1 ? %{$build_args[0]} : @build_args;
    if (my @args = @{$for_self{args} || []}) {
        croak 'Invalid scrypt stanza' unless @args == 2;
        my $salt = $for_self{salt} =
            Crypt::Age::Stanza::decode_base64_no_padding($args[0] || '');
        croak 'Invalid scrypt stanza, wrong salt'
            if length($salt || '') != 16;
        my $wf = $for_self{work_factor} = $args[1] || '';
        croak 'Invalid scrypt stanza, wrong work factor'
            if $wf !~ m{\A [1-9][0-9]* \z}mxs;
        croak 'Invalid scrypt stanza, work factor too big'
            if $wf > MAX_WORK_FACTOR;
    }
    return \%for_self;
};

sub _wrap_key {
    my ($class, $password, $salt_bytes, $work_factor) = @_;

    our $salt_prefix = our $SaltPrefix ||= DEFAULT_SALT_PREFIX;
    my $salt = $salt_prefix . $salt_bytes;
    my $N = 2**$work_factor;
    my $r = our $BlockSize  ||= DEFAULT_BLOCK_SIZE;
    my $p = our $Parallelization ||= DEFAULT_PARALLELIZATON;
    my $len = our $KeyLength ||= DEFAULT_KEY_LENGTH;
    
    return scrypt_pbkdf($password, $salt, $N, $r, $p, $len);
}

sub wrap {
    my ($class, $file_key, $password) = @_;

    my $salt_bytes = random_bytes(16);
    my $work_factor = our $WorkFactor ||= DEFAULT_WORK_FACTOR;
    my $wrap_key = $class->_wrap_key($password, $salt_bytes, $work_factor);

    # Wrap file key
    my $wrapped_key = Crypt::Age::Primitives->wrap_file_key($wrap_key, $file_key);

    # Create stanza
    return $class->new(
        body  => $wrapped_key,
        salt  => $salt_bytes,
        work_factor => $work_factor,
    );
}

=method wrap

    my $stanza = Crypt::Age::Stanza::X25519->wrap($file_key, $recipient_public_key);

Wraps a file key for a recipient.

Parameters:

=over 4

=item * C<$file_key> - The 16-byte file key to wrap

=item * C<$recipient_public_key> - Bech32-encoded public key (C<age1...>)

=back

Generates an ephemeral X25519 keypair, performs key exchange with the
recipient's public key, derives a wrapping key, and wraps the file key.

Returns a L<Crypt::Age::Stanza::X25519> object.

=cut

sub unwrap {
    my ($self, $password) = @_;

    my $salt_bytes = $self->salt;
    my $work_factor = $self->work_factor;
    my $wrap_key = $class->_wrap_key($password, $salt_bytes, $work_factor);

    # Unwrap file key
    my $file_key = eval {
        Crypt::Age::Primitives->unwrap_file_key($wrap_key, $self->body);
    };

    return $file_key;  # Returns undef if unwrap failed
}

=method unwrap

    my $file_key = $stanza->unwrap($identity_secret_key);

Attempts to unwrap the file key using an identity.

Parameters:

=over 4

=item * C<$identity_secret_key> - Bech32-encoded secret key (C<AGE-SECRET-KEY-1...>)

=back

Performs key exchange with the ephemeral public key from the stanza, derives
the wrapping key, and attempts to unwrap the file key.

Returns the 16-byte file key on success, or C<undef> if unwrapping fails
(wrong identity or corrupted data).

=cut

=head1 SEE ALSO

=over 4

=item * L<Crypt::Age> - Main age encryption module

=item * L<Crypt::Age::Stanza> - Base stanza class

=item * L<Crypt::Age::Primitives> - Low-level cryptographic operations

=item * L<Crypt::Age::Keys> - Key encoding/decoding

=back

=cut

1;
