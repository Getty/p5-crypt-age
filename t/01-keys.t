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
# croaks are documented in their own POD as the behaviour a caller can rely on
# ("Dies if the HRP is not ..."), but nothing in t/ asserted either message --
# confirmed by grep before this was written. The natural way to reach them is a
# caller passing the wrong kind of key -- an identity where a public key
# belongs, or the reverse -- so this uses real generated keys rather than a
# synthetic HRP.
#
# Ticket #35 replaced the claim this block used to make. It asserted the old
# wording, "expected 'age', got 'AGE-SECRET-KEY-'", which quoted back the HRP
# that arrived; that HRP is caller material and is no longer named. On this
# path it is only the other type's constant prefix, so nothing leaked here --
# which is exactly why the swap keeps its own assertions and the disclosure is
# measured in the #35 block below, on a string whose HRP carries real key
# characters.
{
    my ($public, $secret) = Crypt::Age::Keys->generate_keypair;

    eval { Crypt::Age::Keys->decode_public_key($secret) };
    like($@, qr/^Invalid public key HRP: expected the literal age prefix, /,
        'decode_public_key on a secret key string reports the documented HRP mismatch');
    unlike($@, qr/AGE-SECRET-KEY-/i,
        'and does not name the HRP it decoded, not even as the other type prefix');

    eval { Crypt::Age::Keys->decode_secret_key($public) };
    like($@, qr/^Invalid secret key HRP: expected the literal age-secret-key- prefix, /,
        'decode_secret_key on a public key string reports the documented HRP mismatch');
    # The mirror assertion cannot be written the same way round: the HRP that
    # arrived here is "age", which is a substring of the expected constant this
    # message names on purpose. What is asserted instead is that the clause
    # reporting what arrived is gone altogether.
    unlike($@, qr/got /,
        'and carries the requirement and the fix rather than what arrived');
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

# Ticket #35: both HRP-mismatch croaks used to interpolate the HRP they
# decoded. bech32_decode returns everything before the last "1" of the string
# it was handed, so that value is a prefix of the caller's own material,
# written into an exception raised inside this module.
#
# Reachability, measured before this block was written rather than assumed, on
# a freshly generated secret key: truncated inside the HRP it dies at "Invalid
# bech32: no separator", truncated at the separator at "Invalid bech32: empty
# data", truncated anywhere in the data part or given trailing junk at "Invalid
# bech32 checksum". None of those quote anything. A string therefore only
# reaches the HRP croak when its Bech32 checksum verifies over the wrong HRP --
# a constructed input rather than a mistyped one, which is why this ticket is
# low and not the disclosure #34 was. Constructed is not unreachable: a string
# whose HRP is the opening characters of a real identity is precisely how those
# characters would be read back out of an exception.
#
# That is the input built below. 32 bytes are encoded under an HRP that is the
# first 31 characters of a freshly generated key, so the checksum verifies and
# the decoded HRP comes back as those 31 characters. The secret half is encoded
# through the lowercased HRP because bech32_verify_checksum checks against
# lc($hrp), and uppercased afterwards so the string is not mixed case -- which
# bech32_decode refuses before it ever looks at the HRP -- and carries the
# key's own casing.
#
# 31 characters and not the whole key, deliberately: a leak assertion has to be
# able to fail in the red state, and what the red state put in the message was
# the decoded HRP, so it is the fixture that has to bound the length. The
# 32-character limit that shaped the same assertions in #34 is perl's own, on
# the strings perl quotes into its dereference errors; these croaks are this
# module's and truncate nothing.
#
# Every assertion below is index() inside ok(), or is() on a count. Never
# like()/unlike()/is_deeply on $err: those print the value they were given when
# they fail, so a red run would write the same key characters into the test
# output that the bug writes into a caller's log.
{
    my ($public, $secret) = Crypt::Age::Keys->generate_keypair;

    my $secret_hrp = substr($secret, 0, 31);
    my $crafted = uc(Crypt::Age::Keys->bech32_encode(lc($secret_hrp), "\x01" x 32));

    # The part of that HRP which is key material rather than type prefix:
    # "AGE-SECRET-KEY-1" is 16 public characters, the 15 after it are not.
    my $secret_chars = substr($secret, 16, 15);

    ok(index($crafted, $secret_hrp) == 0,
        'fixture: the crafted string opens with 31 characters of a real secret key');
    ok(rindex($crafted, '1') == length($secret_hrp),
        'fixture: the last "1" is the one bech32_encode appended, so those 31 characters are the HRP that decodes');

    my ($err, @warn);
    {
        local $SIG{__WARN__} = sub { push @warn, $_[0] };
        local $@;
        eval { Crypt::Age::Keys->decode_secret_key($crafted) };
        $err = $@;
    }

    ok(index($err, 'Invalid secret key HRP: expected the literal age-secret-key- prefix') == 0,
        'a checksum that verifies over the wrong HRP is refused, naming the expected HRP');
    ok(index($err, $secret_hrp) == -1,
        'and no part of the HRP it decoded reaches the message');
    ok(index($err, $secret_chars) == -1,
        'not even the 15 characters of key material that HRP carried');
    is(scalar @warn, 0, 'and nothing warns out of Keys.pm');
    ok(index($err, 'Crypt/Age/Keys.pm') == -1,
        'it croaks: Keys.pm is not blamed as the origin');

    # The same shape on the public half. A public key is not a secret, so this
    # is not a disclosure -- it is the same defect, and the ticket asks for both
    # methods to read the same way, so it is asserted the same way.
    my $public_hrp = substr($public, 0, 31);
    my $crafted_public = Crypt::Age::Keys->bech32_encode($public_hrp, "\x02" x 32);

    ok(rindex($crafted_public, '1') == length($public_hrp),
        'fixture: the same holds for the public half, whose HRP carries a "1" of its own');

    my ($err_public, @warn_public);
    {
        local $SIG{__WARN__} = sub { push @warn_public, $_[0] };
        local $@;
        eval { Crypt::Age::Keys->decode_public_key($crafted_public) };
        $err_public = $@;
    }

    ok(index($err_public, 'Invalid public key HRP: expected the literal age prefix') == 0,
        'the public half is refused the same way, naming the expected HRP');
    ok(index($err_public, $public_hrp) == -1,
        'and no part of the HRP it decoded reaches the message');
    ok(index($err_public, substr($public, 4, 27)) == -1,
        'not even the 27 characters of key material that HRP carried');
    is(scalar @warn_public, 0, 'and nothing warns out of Keys.pm');

    # Counter-proof that the two cases above measure the HRP check and not a
    # string this module could not have decoded in the first place.
    is(length(Crypt::Age::Keys->decode_secret_key($secret)), 32,
        'the untouched secret key still decodes to 32 bytes');
    is(length(Crypt::Age::Keys->decode_public_key($public)), 32,
        'the untouched public key still decodes to 32 bytes');
}

done_testing;
