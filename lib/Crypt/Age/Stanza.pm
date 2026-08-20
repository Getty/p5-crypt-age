package Crypt::Age::Stanza;
# ABSTRACT: Base class for age recipient stanzas
our $VERSION = '0.003';
use Moo;
use Carp qw(croak);
use MIME::Base64 qw(encode_base64 decode_base64);
use namespace::clean;

=head1 SYNOPSIS

    use Crypt::Age::Stanza;

    # Create a stanza
    my $stanza = Crypt::Age::Stanza->new(
        type => 'X25519',
        args => ['base64-encoded-ephemeral-key'],
        body => $wrapped_file_key_bytes,
    );

    # Serialize to string
    my $text = $stanza->to_string;
    # -> X25519 base64-encoded-ephemeral-key
    # base64-wrapped-file-key

=head1 DESCRIPTION

This is the base class for age recipient stanzas.

A stanza represents one way to unwrap the file key. Each recipient in an age
file gets their own stanza. The stanza contains the information needed to
unwrap the file key if you have the corresponding private identity.

Stanzas have three parts:

=over 4

=item * C<type> - The recipient type (e.g., C<X25519>, C<scrypt>)

=item * C<args> - Type-specific arguments (e.g., ephemeral public key)

=item * C<body> - The wrapped file key (base64-encoded in the file)

=back

The stanza format in an age file is:

    -> type arg1 arg2 ...
    base64-wrapped-key-line1
    base64-wrapped-key-line2
    ...

Subclasses like L<Crypt::Age::Stanza::X25519> implement the actual wrapping and
unwrapping logic for specific recipient types.

This is an internal module used by L<Crypt::Age>.

=cut

has type => (
    is       => 'ro',
    required => 1,
);

=attr type

The stanza type (e.g., C<X25519>, C<scrypt>).

Required.

=cut

has args => (
    is      => 'ro',
    default => sub { [] },
);

=attr args

ArrayRef of type-specific arguments.

For X25519 stanzas, this is the base64-encoded ephemeral public key.

=cut

has body => (
    is      => 'ro',
    default => '',
);

=attr body

The wrapped file key as raw bytes.

This is base64-encoded when serialized to the age file format.

=cut

sub encode_base64_no_padding {
    my ($data) = @_;
    my $encoded = encode_base64($data, '');
    $encoded =~ s/=+$//;  # Remove padding
    return $encoded;
}

sub decode_base64_no_padding {
    my ($encoded) = @_;

    # "decoders MUST reject non-canonical encodings and encodings ending with
    # '=' padding characters" -- c2sp.org/age. MIME::Base64 does neither: it
    # silently skips characters outside the alphabet, drops a stray trailing
    # character, and ignores the unused bits of the last group. Every check
    # below is therefore ours, and none of them names $encoded in its message --
    # a stanza body is wrapped key material.
    croak "Invalid base64: '=' padding is not allowed in the age format"
        if $encoded =~ m{=};
    croak "Invalid base64: character outside the RFC 4648 section 4 alphabet"
        if $encoded =~ m{[^A-Za-z0-9+/]};
    croak "Invalid base64: length is not a valid unpadded encoding"
        if length($encoded) % 4 == 1;

    my $pad = (4 - length($encoded) % 4) % 4;
    my $decoded = decode_base64($encoded . ('=' x $pad));

    # Re-encode and compare. This is what catches non-canonical trailing bits:
    # the unused low bits of the final group must be zero, so the canonical
    # encoding of the decoded bytes has to be byte-identical to the input.
    croak "Invalid base64: non-canonical encoding"
        unless encode_base64_no_padding($decoded) eq $encoded;

    return $decoded;
}

sub to_string {
    my ($self) = @_;

    my @parts = ('->', $self->type, @{$self->args});
    my $header_line = join(' ', @parts);

    my $body_b64 = encode_base64_no_padding($self->body);

    # Split into 64-char lines. The ABNF is
    #   stanza = arg-line *full-line final-line
    #   final-line = *63base64char LF
    # so the final line is at most 63 characters and a body whose encoding is an
    # exact multiple of 64 MUST be followed by an empty final line -- hence >=
    # and not >. Header::parse's matching `last if $len < 64` depends on it, and
    # so does the header MAC.
    my @lines = ($header_line);
    while (length($body_b64) >= 64) {
        push @lines, substr($body_b64, 0, 64, '');
    }
    push @lines, $body_b64;  # final line, empty when the body ended flush at 64

    return join("\n", @lines);
}

=method to_string

    my $text = $stanza->to_string;

Serializes the stanza to age file format.

Returns a multi-line string with the stanza header (C<-E<gt> type args...>) and
base64-encoded body wrapped at 64 characters per line.

The last body line is always shorter than 64 characters, as the format requires.
A body whose base64 encoding is an exact multiple of 64 characters is therefore
followed by an empty final line, and the returned string ends in a newline.

=cut

=head1 FUNCTIONS

=func encode_base64_no_padding

    my $encoded = Crypt::Age::Stanza::encode_base64_no_padding($bytes);

Encodes bytes to base64 without padding (no trailing C<=> characters).

This is the encoding used for all base64 in the age format.

=cut

=func decode_base64_no_padding

    my $bytes = Crypt::Age::Stanza::decode_base64_no_padding($encoded);

Decodes unpadded base64, strictly.

The age format specifies RFC 4648 section 4 base64 without padding, and requires
that decoders reject anything else. This function therefore dies rather than
repairing its input when:

=over 4

=item * the input contains C<=> padding characters

=item * the input contains a character outside the standard base64 alphabet

=item * the input length is congruent to 1 modulo 4, which no encoding produces

=item * the encoding is non-canonical, i.e. the unused trailing bits of the final
group are not zero, so that some other encoding of the same bytes exists

=back

The error messages name the reason and never the input, which may be key
material.

=cut

=head1 SEE ALSO

=over 4

=item * L<Crypt::Age> - Main age encryption module

=item * L<Crypt::Age::Header> - Header parsing and generation

=item * L<Crypt::Age::Stanza::X25519> - X25519 recipient stanza implementation

=back

=cut

1;
