package Crypt::Age::Header;
# ABSTRACT: age file header parsing and generation
our $VERSION = '0.002';
use Moo;
use Carp qw(croak);
use Crypt::Age::Primitives;
use Crypt::Age::Stanza;
use Crypt::Age::Stanza::X25519;
use namespace::clean;

=head1 SYNOPSIS

    use Crypt::Age::Header;

    # Create header for encryption
    my $header = Crypt::Age::Header->create($file_key, \@recipient_public_keys);
    my $header_text = $header->to_string;

    # Parse header during decryption
    my $offset = 0;
    my $header = Crypt::Age::Header->parse(\$ciphertext, \$offset);

    # Unwrap file key
    my $file_key = $header->unwrap_file_key(\@identity_secret_keys);

=head1 DESCRIPTION

This module handles parsing and generation of age file headers.

An age file header is a text section at the beginning of an age file that contains:

=over 4

=item * Version line (C<age-encryption.org/v1>)

=item * One or more recipient stanzas (each wrapping the file key)

=item * MAC footer (authenticates the header)

=back

The header format is:

    age-encryption.org/v1
    -> X25519 <base64-ephemeral-public-key>
    <base64-wrapped-file-key>
    --- <base64-mac>

This is an internal module used by L<Crypt::Age>.

=cut

use constant VERSION_LINE => "age-encryption.org/v1";

has stanzas => (
    is      => 'ro',
    default => sub { [] },
);

=attr stanzas

ArrayRef of L<Crypt::Age::Stanza> objects representing recipient stanzas.

Each stanza wraps the file key for one recipient.

=cut

has mac => (
    is => 'rw',
);

=attr mac

The header MAC as raw bytes (32 bytes).

Used to authenticate the header and verify that the correct file key was unwrapped.

=cut

has _bytes => (
    is => 'lazy',
);

# The header bytes the MAC is computed over: everything up to and including the
# '---' of the footer line, without the space after it and without a trailing
# newline. Internal, hence the leading underscore and the matching constructor
# key used by parse_from_fh.
#
# On the read path parse_from_fh passes the literal bytes it read, so the MAC is
# verified against what the file actually contained. On the write path there is
# nothing to capture and the builder below re-serializes the stanzas instead.

sub create {
    my ($class, $file_key, $recipients) = @_;

    my @stanzas;
    for my $recipient (@$recipients) {
        if ($recipient =~ /^age1/) {
            push @stanzas, Crypt::Age::Stanza::X25519->wrap($file_key, $recipient);
        } else {
            croak "Unsupported recipient format: $recipient";
        }
    }

    my $header = $class->new(stanzas => \@stanzas);

    # Compute and set MAC
    my $header_bytes = $header->_bytes;
    my $mac = Crypt::Age::Primitives->compute_header_mac($file_key, $header_bytes);
    $header->mac($mac);

    return $header;
}

=method create

    my $header = Crypt::Age::Header->create($file_key, \@recipients);

Creates a new header for encrypting to multiple recipients.

Parameters:

=over 4

=item * C<$file_key> - The 16-byte file key to wrap

=item * C<\@recipients> - ArrayRef of Bech32-encoded public keys (C<age1...>)

=back

Returns a L<Crypt::Age::Header> object with stanzas for each recipient and a
computed MAC.

=cut

sub to_string {
    my ($self) = @_;

    my @lines = (VERSION_LINE);

    for my $stanza (@{$self->stanzas}) {
        push @lines, $stanza->to_string;
    }

    # MAC line
    my $mac_b64 = Crypt::Age::Stanza::encode_base64_no_padding($self->mac);
    push @lines, "--- $mac_b64";

    return join("\n", @lines) . "\n";
}

=method to_string

    my $header_text = $header->to_string;

Serializes the header to text format.

Returns a string containing the version line, all stanzas, and the MAC footer,
suitable for writing to the beginning of an age file.

=cut

sub _build__bytes {
    my ($self) = @_;

    my @lines = (VERSION_LINE);

    for my $stanza (@{$self->stanzas}) {
        push @lines, $stanza->to_string;
    }

    # For MAC, we include everything up to but not including the MAC itself
    # The footer line is "---" (without the MAC)
    push @lines, "---";

    return join("\n", @lines);
}

sub parse_from_fh {
    my ($class, $fh) = @_;

    # make sure to read the whole thing in the correct way
    binmode($fh, ':raw') or croak "binmode: $!";
    local $/ = "\x{0a}";

    # $header will eventually contain the whole header, for MAC validation.
    # We start from the first line.
    my $bytes = <$fh>;

    # Check version
    chomp(my $version_line = $bytes); # remove \x{0a}
    croak "Invalid age version: $version_line" unless $version_line eq VERSION_LINE;

    # read the rest of the header
    my (@stanzas, $mac);
    my $n = 0;
    while (<$fh>) {
        if (my ($mac64) = m{\A ---\x{20} (\S{43}) \x{0a} \z}mxs) {
            $bytes .= '---';
            $mac = Crypt::Age::Stanza::decode_base64_no_padding($mac64);
            last;
        }
        ++$n;
        my ($ta) = m{\A ->\x{20} (\S+ (?:\x{20}\S+)*) \x{0a} \z}mxs
            or croak "Invalid age stanza #$n start line: <$_>";

        $bytes .= $_;

        # Read stanza's body lines
        my $body_b64 = '';
        my $body_completed = 0;
        while (<$fh>) {
            $bytes .= $_;
            chomp;
            my $len = length($_);
            croak "Invalid age stanza #$n body" if $len > 64;
            $body_b64 .= $_;
            if ($len < 64) {
                $body_completed = 1;
                last;
            }
        }
        # "The body MUST end with a line shorter than 64 characters, which
        #  MAY be empty."
        croak "Invalid age stanza #$n body" unless $body_completed;

        my ($type, @args) = split m{\x{20}}mxs, $ta;
        my $body = Crypt::Age::Stanza::decode_base64_no_padding($body_b64);

        my $stanza_class = 'Crypt::Age::Stanza';
        if ($type eq 'X25519') {
            $stanza_class = 'Crypt::Age::Stanza::X25519';
        }

        push @stanzas, $stanza_class->new(
            type => $type,
            args => \@args,
            body => $body,
        );
    }
    croak "Invalid age file, no valid header MAC line" unless length($mac // '');

    return $class->new(
        stanzas => \@stanzas,
        _bytes  => $bytes,
        mac     => $mac,
    );
}

sub parse {
    my ($class, $data_ref, $offset_ref) = @_;
    open my $fh, '<:raw', $data_ref or croak "Invalid age input: cannot read";
    seek($fh, $$offset_ref // 0, 0);
    my $retval = $class->parse_from_fh($fh);
    $$offset_ref = tell($fh);
    return $retval;
}

=method parse

    my $header = Crypt::Age::Header->parse(\$data, \$offset);

Parses an age header from encrypted data.

Parameters:

=over 4

=item * C<\$data> - ScalarRef to the complete age file data

=item * C<\$offset> - ScalarRef to offset, updated to point past the header

=back

Returns a L<Crypt::Age::Header> object. The C<$offset> is updated to point to
the start of the payload.

Dies if the header format is invalid.

=cut

sub verify_mac {
    my ($self, $file_key) = @_;

    my $header_bytes = $self->_bytes;
    my $expected_mac = Crypt::Age::Primitives->compute_header_mac($file_key, $header_bytes);

    return $self->mac eq $expected_mac;
}

=method verify_mac

    my $ok = $header->verify_mac($file_key);

Verifies that the header MAC is correct for the given file key.

Returns true if the MAC is valid, false otherwise. Used to confirm that the
correct file key was unwrapped from a stanza.

=cut

sub unwrap_file_key {
    my ($self, $identities) = @_;

    for my $identity (@$identities) {
        for my $stanza (@{$self->stanzas}) {
            if ($stanza->isa('Crypt::Age::Stanza::X25519') && $identity =~ /^AGE-SECRET-KEY-1/i) {
                my $file_key = $stanza->unwrap($identity);
                if (defined $file_key && $self->verify_mac($file_key)) {
                    return $file_key;
                }
            }
        }
    }

    croak "No matching identity found";
}

=method unwrap_file_key

    my $file_key = $header->unwrap_file_key(\@identities);

Attempts to unwrap the file key using one or more identities.

Parameters:

=over 4

=item * C<\@identities> - ArrayRef of Bech32-encoded secret keys (C<AGE-SECRET-KEY-1...>)

=back

Tries each identity against each stanza until one successfully unwraps the file
key and verifies the MAC. Returns the 16-byte file key.

Dies if no matching identity is found or if MAC verification fails.

=cut

=head1 SEE ALSO

=over 4

=item * L<Crypt::Age> - Main age encryption module

=item * L<Crypt::Age::Stanza> - Base stanza class

=item * L<Crypt::Age::Stanza::X25519> - X25519 recipient stanza

=back

=cut

1;
