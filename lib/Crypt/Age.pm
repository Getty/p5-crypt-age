package Crypt::Age;
# ABSTRACT: Perl implementation of age encryption (age-encryption.org)

use Moo;
use Carp qw(croak);
use Crypt::Age::Keys;
use Crypt::Age::Primitives;
use Crypt::Age::Header;
use namespace::clean;

our $VERSION = '0.001';

sub generate_keypair {
    my ($class) = @_;
    return Crypt::Age::Keys->generate_keypair;
}

sub encrypt {
    my ($class, %args) = @_;
    my $plaintext  = $args{plaintext}  // croak "plaintext required";
    my $recipients = $args{recipients} // croak "recipients required";

    croak "recipients must be an array ref" unless ref($recipients) eq 'ARRAY';
    croak "at least one recipient required" unless @$recipients;

    # Generate random file key
    my $file_key = Crypt::Age::Primitives->generate_file_key;

    # Create header with wrapped file key for each recipient
    my $header = Crypt::Age::Header->create($file_key, $recipients);

    # Derive payload key and encrypt
    my $payload_key = Crypt::Age::Primitives->derive_payload_key($file_key);
    my $encrypted_payload = Crypt::Age::Primitives->encrypt_payload($payload_key, $plaintext);

    return $header->to_string . $encrypted_payload;
}

sub decrypt {
    my ($class, %args) = @_;
    my $ciphertext = $args{ciphertext} // croak "ciphertext required";
    my $identities = $args{identities} // croak "identities required";

    croak "identities must be an array ref" unless ref($identities) eq 'ARRAY';
    croak "at least one identity required" unless @$identities;

    # Parse header
    my $offset = 0;
    my $header = Crypt::Age::Header->parse(\$ciphertext, \$offset);

    # Unwrap file key using identities
    my $file_key = $header->unwrap_file_key($identities);

    # Extract and decrypt payload
    my $encrypted_payload = substr($ciphertext, $offset);
    my $payload_key = Crypt::Age::Primitives->derive_payload_key($file_key);

    return Crypt::Age::Primitives->decrypt_payload($payload_key, $encrypted_payload);
}

sub encrypt_file {
    my ($class, %args) = @_;
    my $input      = $args{input}      // croak "input required";
    my $output     = $args{output}     // croak "output required";
    my $recipients = $args{recipients} // croak "recipients required";

    open my $in_fh, '<:raw', $input
        or croak "Cannot open input file '$input': $!";
    my $plaintext = do { local $/; <$in_fh> };
    close $in_fh;

    my $ciphertext = $class->encrypt(
        plaintext  => $plaintext,
        recipients => $recipients,
    );

    open my $out_fh, '>:raw', $output
        or croak "Cannot open output file '$output': $!";
    print $out_fh $ciphertext;
    close $out_fh;

    return 1;
}

sub decrypt_file {
    my ($class, %args) = @_;
    my $input      = $args{input}      // croak "input required";
    my $output     = $args{output}     // croak "output required";
    my $identities = $args{identities} // croak "identities required";

    open my $in_fh, '<:raw', $input
        or croak "Cannot open input file '$input': $!";
    my $ciphertext = do { local $/; <$in_fh> };
    close $in_fh;

    my $plaintext = $class->decrypt(
        ciphertext => $ciphertext,
        identities => $identities,
    );

    open my $out_fh, '>:raw', $output
        or croak "Cannot open output file '$output': $!";
    print $out_fh $plaintext;
    close $out_fh;

    return 1;
}

1;

__END__

=head1 NAME

Crypt::Age - Perl implementation of age encryption (age-encryption.org)

=head1 SYNOPSIS

    use Crypt::Age;

    # Generate keypair
    my ($public, $secret) = Crypt::Age->generate_keypair();
    # $public  = "age1ql3z7hjy..."
    # $secret  = "AGE-SECRET-KEY-1..."

    # Encrypt
    my $encrypted = Crypt::Age->encrypt(
        plaintext  => "Hello, World!",
        recipients => [$public],
    );

    # Decrypt
    my $decrypted = Crypt::Age->decrypt(
        ciphertext => $encrypted,
        identities => [$secret],
    );

    # File operations
    Crypt::Age->encrypt_file(
        input      => 'secret.txt',
        output     => 'secret.txt.age',
        recipients => [$public],
    );

    Crypt::Age->decrypt_file(
        input      => 'secret.txt.age',
        output     => 'secret.txt',
        identities => [$secret],
    );

=head1 DESCRIPTION

Crypt::Age is a pure Perl implementation of the age encryption format,
compatible with the reference Go implementation (filippo.io/age) and
the Rust implementation (rage).

age is a simple, modern and secure file encryption tool with small explicit
keys, no config options, and UNIX-style composability.

=head1 METHODS

=head2 generate_keypair

    my ($public_key, $secret_key) = Crypt::Age->generate_keypair();

Generates a new X25519 keypair. Returns the public key (C<age1...>) and
secret key (C<AGE-SECRET-KEY-1...>) as Bech32-encoded strings.

=head2 encrypt

    my $ciphertext = Crypt::Age->encrypt(
        plaintext  => $data,
        recipients => \@public_keys,
    );

Encrypts plaintext for one or more recipients. Recipients are specified
as Bech32-encoded public keys (C<age1...>). Returns the encrypted data
in age format.

=head2 decrypt

    my $plaintext = Crypt::Age->decrypt(
        ciphertext => $encrypted,
        identities => \@secret_keys,
    );

Decrypts age-encrypted data using one or more identities. Identities are
specified as Bech32-encoded secret keys (C<AGE-SECRET-KEY-1...>).

=head2 encrypt_file

    Crypt::Age->encrypt_file(
        input      => 'plaintext.txt',
        output     => 'encrypted.age',
        recipients => \@public_keys,
    );

Encrypts a file. The output file will be in age format.

=head2 decrypt_file

    Crypt::Age->decrypt_file(
        input      => 'encrypted.age',
        output     => 'plaintext.txt',
        identities => \@secret_keys,
    );

Decrypts an age-encrypted file.

=head1 KEY FORMAT

=head2 Public Keys

Public keys are Bech32-encoded X25519 public keys with the human-readable
part C<age>:

    age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

=head2 Secret Keys

Secret keys are uppercase Bech32-encoded X25519 secret keys with the
human-readable part C<AGE-SECRET-KEY->:

    AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ3290DG

=head1 INTEROPERABILITY

This module is designed to be compatible with:

=over 4

=item * L<age|https://github.com/FiloSottile/age> - Reference Go implementation

=item * L<rage|https://github.com/str4d/rage> - Rust implementation

=back

Files encrypted with Crypt::Age can be decrypted with these tools and vice versa.

=head1 SEE ALSO

=over 4

=item * L<https://age-encryption.org> - age encryption homepage

=item * L<https://github.com/C2SP/C2SP/blob/main/age.md> - age format specification

=item * L<CryptX> - Cryptographic toolkit used by this module

=back

=cut
