package Crypt::Age::Header;
# ABSTRACT: age file header parsing and generation

use Moo;
use Carp qw(croak);
use Crypt::Age::Primitives;
use Crypt::Age::Stanza;
use Crypt::Age::Stanza::X25519;
use namespace::clean;

use constant VERSION_LINE => "age-encryption.org/v1";

has stanzas => (
    is      => 'ro',
    default => sub { [] },
);

has mac => (
    is => 'rw',
);

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

    my $data = $$data_ref;
    my $pos = $$offset_ref // 0;

    # Find header end (the line starting with ---)
    my $header_end = index($data, "\n---", $pos);
    croak "Invalid age file: no header footer found" if $header_end < 0;

    # Extract header text
    my $header_text = substr($data, $pos, $header_end - $pos + 1);
    my @lines = split /\n/, $header_text;

    # Check version
    my $version_line = shift @lines;
    croak "Invalid age version: $version_line" unless $version_line eq VERSION_LINE;

    # Parse stanzas
    my @stanzas;
    while (@lines) {
        my $line = shift @lines;
        last if $line =~ /^---/;

        if ($line =~ /^-> (\S+)\s*(.*)/) {
            my $type = $1;
            my @args = split /\s+/, $2;

            # Read body lines
            my $body_b64 = '';
            while (@lines && $lines[0] !~ /^->/ && $lines[0] !~ /^---/) {
                my $body_line = shift @lines;
                $body_b64 .= $body_line;
                last if length($body_line) < 64;  # Short line ends body
            }

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
    }

    # Parse MAC line
    $pos = $header_end + 1;  # Position after the newline before ---
    my $footer_end = index($data, "\n", $pos);
    $footer_end = length($data) if $footer_end < 0;

    my $footer_line = substr($data, $pos, $footer_end - $pos);
    croak "Invalid footer: $footer_line" unless $footer_line =~ /^--- (\S+)$/;
    my $mac = Crypt::Age::Stanza::decode_base64_no_padding($1);

    # Update offset to point after header
    $$offset_ref = $footer_end + 1;

    return $class->new(
        stanzas => \@stanzas,
        mac     => $mac,
    );
}

sub verify_mac {
    my ($self, $file_key) = @_;

    my $header_bytes = $self->_header_bytes_for_mac;
    my $expected_mac = Crypt::Age::Primitives->compute_header_mac($file_key, $header_bytes);

    return $self->mac eq $expected_mac;
}

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

1;
