#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Crypt::Age::Keys;

# Test keypair generation
{
    my ($public, $secret) = Crypt::Age::Keys->generate_keypair;

    ok(defined $public, 'public key generated');
    ok(defined $secret, 'secret key generated');

    like($public, qr/^age1[a-z0-9]+$/, 'public key has correct format');
    like($secret, qr/^AGE-SECRET-KEY-1[A-Z0-9]+$/, 'secret key has correct format');

    # Keys should be deterministic length
    is(length($public), 62, 'public key has correct length');
    is(length($secret), 74, 'secret key has correct length');
}

# Test public key encoding/decoding roundtrip
{
    my $raw_key = "\x00" x 32;  # 32 zero bytes
    my $encoded = Crypt::Age::Keys->encode_public_key($raw_key);
    my $decoded = Crypt::Age::Keys->decode_public_key($encoded);

    is($decoded, $raw_key, 'public key roundtrip');
}

# Test secret key encoding/decoding roundtrip
{
    my $raw_key = "\xff" x 32;  # 32 0xff bytes
    my $encoded = Crypt::Age::Keys->encode_secret_key($raw_key);
    my $decoded = Crypt::Age::Keys->decode_secret_key($encoded);

    is($decoded, $raw_key, 'secret key roundtrip');
}

# Test public_key_from_secret
{
    my ($public, $secret) = Crypt::Age::Keys->generate_keypair;
    my $derived_public = Crypt::Age::Keys->public_key_from_secret($secret);

    is($derived_public, $public, 'public key derived from secret matches');
}

# Test error handling
{
    eval { Crypt::Age::Keys->encode_public_key("short") };
    like($@, qr/must be 32 bytes/, 'rejects short public key');

    eval { Crypt::Age::Keys->decode_public_key("invalid") };
    like($@, qr/Invalid bech32/, 'rejects invalid bech32');
}

# Test Bech32 with known test vectors
{
    # These are test vectors from BIP-173
    my $encoded = Crypt::Age::Keys->bech32_encode('a', '');
    is($encoded, 'a12uel5l', 'bech32 empty data');

    # Test decoding
    my ($hrp, $data) = Crypt::Age::Keys->bech32_decode('a12uel5l');
    is($hrp, 'a', 'bech32 decode hrp');
    is($data, '', 'bech32 decode empty data');
}

# Ticket #17: bech32_decode must reject a string that mixes upper- and
# lowercase, per BIP-173 ("Decoders MUST NOT accept strings where some
# characters are uppercase and some are lowercase") and c2sp.org/age, which
# repeats the rule for age keys specifically. Mutate exactly one letter in
# the data part of an otherwise-valid key -- everything else, including the
# checksum, is untouched -- and confirm that alone is fatal.
{
    my ($public, $secret) = Crypt::Age::Keys->generate_keypair;

    my $pub_sep = rindex($public, '1');
    my $pub_hrp = substr($public, 0, $pub_sep + 1);
    my $pub_data = substr($public, $pub_sep + 1);
    ok($pub_data =~ s/([a-z])/\U$1/, 'found a lowercase letter to mutate in public key data')
        or die 'no lowercase letter in generated public key data -- fixture assumption broken';
    my $mixed_public = $pub_hrp . $pub_data;

    eval { Crypt::Age::Keys->decode_public_key($mixed_public) };
    like($@, qr/Invalid bech32: mixed case/, 'mixed-case public key rejected');

    my $sec_sep = rindex($secret, '1');
    my $sec_hrp = substr($secret, 0, $sec_sep + 1);
    my $sec_data = substr($secret, $sec_sep + 1);
    ok($sec_data =~ s/([A-Z])/\L$1/, 'found an uppercase letter to mutate in secret key data')
        or die 'no uppercase letter in generated secret key data -- fixture assumption broken';
    my $mixed_secret = $sec_hrp . $sec_data;

    eval { Crypt::Age::Keys->decode_secret_key($mixed_secret) };
    like($@, qr/Invalid bech32: mixed case/, 'mixed-case secret key rejected');
}

# Ticket #17: the case rule cuts both ways -- an all-uppercase public key and
# an all-lowercase secret key are the forms rage accepts (age is stricter
# about the type prefix, which is a separate, pre-existing distinction this
# ticket does not touch) and must keep decoding, to the *same bytes* as the
# canonically-cased form this module itself emits.
{
    my ($public, $secret) = Crypt::Age::Keys->generate_keypair;

    my $public_bytes = Crypt::Age::Keys->decode_public_key($public);
    my $public_bytes_upper = Crypt::Age::Keys->decode_public_key(uc($public));
    is($public_bytes_upper, $public_bytes,
        'all-uppercase public key decodes to the same bytes as the canonical lowercase form');

    my $secret_bytes = Crypt::Age::Keys->decode_secret_key($secret);
    my $secret_bytes_lower = Crypt::Age::Keys->decode_secret_key(lc($secret));
    is($secret_bytes_lower, $secret_bytes,
        'all-lowercase secret key decodes to the same bytes as the canonical uppercase form');
}

# Ticket #17: the BIP-173 test vector table itself, as an external anchor
# rather than a string we generated. "A12UEL5L" and "a12uel5l" are both
# listed there as valid (an all-uppercase and an all-lowercase encoding of
# the same empty-data string with HRP "a"); "a12UEL5L" and "A12uel5l" are
# mixed-case variants of that same vector, rejected under the mixed-case
# rule BIP-173 states in prose ("Decoders MUST NOT accept strings where some
# characters are uppercase and some are lowercase") rather than as separate
# entries in its invalid-vector table.
{
    my ($hrp_lower, $data_lower) = Crypt::Age::Keys->bech32_decode('a12uel5l');
    is($hrp_lower, 'a', 'BIP-173 vector a12uel5l: hrp');
    is($data_lower, '', 'BIP-173 vector a12uel5l: empty data');

    my ($hrp_upper, $data_upper) = Crypt::Age::Keys->bech32_decode('A12UEL5L');
    is($hrp_upper, 'A', 'BIP-173 vector A12UEL5L: hrp');
    is($data_upper, '', 'BIP-173 vector A12UEL5L: empty data');

    for my $mixed (qw(a12UEL5L A12uel5l)) {
        eval { Crypt::Age::Keys->bech32_decode($mixed) };
        like($@, qr/Invalid bech32: mixed case/, "BIP-173 vector $mixed rejected as mixed case");
    }
}

done_testing;
