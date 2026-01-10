package Crypt::Age::Stanza;
# ABSTRACT: Base class for age recipient stanzas

use Moo;
use Carp qw(croak);
use MIME::Base64 qw(encode_base64 decode_base64);
use namespace::clean;

has type => (
    is       => 'ro',
    required => 1,
);

has args => (
    is      => 'ro',
    default => sub { [] },
);

has body => (
    is      => 'ro',
    default => '',
);

sub encode_body_base64 {
    my ($self) = @_;
    return encode_base64_no_padding($self->body);
}

sub encode_base64_no_padding {
    my ($data) = @_;
    my $encoded = encode_base64($data, '');
    $encoded =~ s/=+$//;  # Remove padding
    return $encoded;
}

sub decode_base64_no_padding {
    my ($encoded) = @_;
    # Add padding back if needed
    my $pad = (4 - length($encoded) % 4) % 4;
    $encoded .= '=' x $pad;
    return decode_base64($encoded);
}

sub to_string {
    my ($self) = @_;

    my @parts = ('->', $self->type, @{$self->args});
    my $header_line = join(' ', @parts);

    my $body_b64 = encode_base64_no_padding($self->body);

    # Split into 64-char lines
    my @lines = ($header_line);
    while (length($body_b64) > 64) {
        push @lines, substr($body_b64, 0, 64, '');
    }
    push @lines, $body_b64;  # Last line (may be empty for exact multiple of 64)

    return join("\n", @lines);
}

sub to_bytes_for_mac {
    my ($self) = @_;
    # For MAC computation, stanzas are serialized as in the header
    return $self->to_string . "\n";
}

1;
