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
    my $header_bytes = $header->_header_bytes_for_mac;
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

sub _header_bytes_for_mac {
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

sub parse {
    my ($class, $data_ref, $offset_ref) = @_;

    my $pos = $$offset_ref // 0;

    # Find header end (the line starting with ---)
    my $header_end = index($$data_ref, "\x{0a}---", $pos);
    croak "Invalid age file: no header footer found" if $header_end < 0;

    # Extract header text up to the header's footer, including the LF
    my $header_text = substr($$data_ref, $pos, $header_end - $pos + 1);

    # Parse MAC line -->  end = "--- " 43base64char LF
    $pos = $header_end + 1;  # Position after the newline before ---
    my $end_line = substr($$data_ref, $pos, 4 + 43 + 1);
    my ($mac64) = $end_line =~ m{\A ---\x{20} (\S{43}) \x{0a} \z}mxs
        or croak "Invalid footer: <$end_line>";
    my $mac = Crypt::Age::Stanza::decode_base64_no_padding($mac64);
    $pos += length($end_line);

    my @lines = split /\x{0a}/, $header_text;

    # Check version
    my $version_line = shift @lines;
    croak "Invalid age version: $version_line" unless $version_line eq VERSION_LINE;

    # Parse stanzas
    my @stanzas;
    while (@lines) {
        my $n = @stanzas + 1;  # for diagnostic messages
        my $line = shift @lines;
        my ($argline) = $line =~ m{\A ->\x{20} (\S+ (?:\x{20}\S+)*) \z}mxs
            or croak "Invalid age stanza #$n start line: <$line>";
        my ($type, @args) = split m{\x{20}}mxs, $argline;

        # Read body lines
        my $body_b64 = '';
        my $body_completed = 0;
        while (@lines && ! $body_completed) {
            my $body_line = shift @lines;
            my $len = length($body_line);
            croak "Invalid age stanza #$n body" if $len > 64;
            $body_b64 .= $body_line;
            $body_completed = $len < 64;
        }
        # "The body MUST end with a line shorter than 64 characters, which
        #  MAY be empty."
        croak "Invalid age stanza #$n body" unless $body_completed;
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

    # Update offset to point after header
    $$offset_ref = $pos;

    return $class->new(
        stanzas => \@stanzas,
        mac     => $mac,
    );
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

    my $header_bytes = $self->_header_bytes_for_mac;
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
