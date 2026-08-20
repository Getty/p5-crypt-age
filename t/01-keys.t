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

# Ticket #20: decode_public_key's and decode_secret_key's HRP-mismatch
# croaks (Keys.pm:101, Keys.pm:138) are documented in their own POD as the
# behaviour a caller can rely on ("Dies if the HRP is not ..."), but nothing
# in t/ asserted either message -- confirmed by grep before this was written.
# The natural way to reach them is a caller passing the wrong kind of key --
# an identity where a public key belongs, or the reverse -- so this uses real
# generated keys rather than a synthetic HRP. bech32_decode does not
# lowercase the HRP it returns (only the checksum check does that
# internally), so the secret key's HRP surfaces in the message exactly as
# the key carries it: uppercase.
{
    my ($public, $secret) = Crypt::Age::Keys->generate_keypair;

    eval { Crypt::Age::Keys->decode_public_key($secret) };
    like($@, qr/^Invalid public key HRP: expected 'age', got 'AGE-SECRET-KEY-'/,
        'decode_public_key on a secret key string reports the documented HRP mismatch');

    eval { Crypt::Age::Keys->decode_secret_key($public) };
    like($@, qr/^Invalid secret key HRP: expected 'age-secret-key-', got 'age'/,
        'decode_secret_key on a public key string reports the documented HRP mismatch');
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

# Ticket #23: the "character outside the Bech32 charset" croak used to
# interpolate the offending character. No character of an encoded age key can
# reach that branch -- every character of one is inside the charset by
# construction, measured over freshly generated keys -- but bech32_decode is
# public and takes any string, so what could be quoted back was one byte of
# some other secret handed to it by mistake, a passphrase say. It now reports a
# 0-based offset into the string that was passed in.
#
# The marker characters are deliberately non-alphanumeric: no message this
# distribution writes contains one, so searching the exception for the
# character is a real assertion. Searching for a "b" would always find one --
# the word "bech32" is in the message itself.
{
    for my $case (
        [ 'age1qpzry9!x8gf', '!', 10 ],
        [ 'age1q#',          '#',  5 ],
    ) {
        my ($input, $marker, $offset) = @$case;

        is(index($input, $marker), $offset,
            "fixture: marker sits at offset $offset of the input");

        eval { Crypt::Age::Keys->bech32_decode($input) };
        my $err = $@;

        like($err, qr/\AInvalid bech32 character at offset \Q$offset\E: /,
            "out-of-charset character reported by its offset $offset");

        # The same character counted from the start of the data part is a
        # different, smaller number; this pins which of the two the message
        # means, since only the whole-string offset is usable by a caller who
        # has not itself located the separator.
        my $data_offset = $offset - rindex($input, '1') - 1;
        unlike($err, qr/at offset \Q$data_offset\E:/,
            'the number is an offset into the whole string, not into the data part');

        ok(index($err, $marker) < 0,
            'the offending character itself does not appear in the message');
    }
}

done_testing;
