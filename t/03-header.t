#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Crypt::Age::Header;
use Crypt::Age::Keys;
use Crypt::Age::Primitives;
use Crypt::Age::Stanza;
use Crypt::Age::Stanza::X25519;

# Test header creation
{
    my ($public, $secret) = Crypt::Age::Keys->generate_keypair;
    my $file_key = Crypt::Age::Primitives->generate_file_key;

    my $header = Crypt::Age::Header->create($file_key, [$public]);

    ok(defined $header, 'header created');
    is(scalar @{$header->stanzas}, 1, 'one stanza');
    ok(defined $header->mac, 'MAC computed');
}

# Test header to_string format
{
    my ($public, $secret) = Crypt::Age::Keys->generate_keypair;
    my $file_key = Crypt::Age::Primitives->generate_file_key;

    my $header = Crypt::Age::Header->create($file_key, [$public]);
    my $str = $header->to_string;

    like($str, qr/^age-encryption\.org\/v1\n/, 'starts with version');
    like($str, qr/\n-> X25519 /, 'contains X25519 stanza');
    like($str, qr/\n--- [A-Za-z0-9+\/]+\n$/, 'ends with MAC line');
}

# Test header parse and roundtrip
{
    my ($public, $secret) = Crypt::Age::Keys->generate_keypair;
    my $file_key = Crypt::Age::Primitives->generate_file_key;

    my $header = Crypt::Age::Header->create($file_key, [$public]);
    my $str = $header->to_string;

    my $offset = 0;
    my $parsed = Crypt::Age::Header->parse(\$str, \$offset);

    is(scalar @{$parsed->stanzas}, 1, 'parsed one stanza');
    is($parsed->stanzas->[0]->type, 'X25519', 'stanza type is X25519');
    is($parsed->mac, $header->mac, 'MAC matches');
    is($offset, length($str), 'offset at end of header');
}

# Test MAC verification
{
    my ($public, $secret) = Crypt::Age::Keys->generate_keypair;
    my $file_key = Crypt::Age::Primitives->generate_file_key;

    my $header = Crypt::Age::Header->create($file_key, [$public]);

    ok($header->verify_mac($file_key), 'MAC verifies with correct key');

    my $wrong_key = Crypt::Age::Primitives->generate_file_key;
    ok(!$header->verify_mac($wrong_key), 'MAC fails with wrong key');
}

# Test file key unwrapping
{
    my ($public, $secret) = Crypt::Age::Keys->generate_keypair;
    my $file_key = Crypt::Age::Primitives->generate_file_key;

    my $header = Crypt::Age::Header->create($file_key, [$public]);
    my $unwrapped = $header->unwrap_file_key([$secret]);

    is($unwrapped, $file_key, 'unwrapped file key matches');
}

# Test multiple recipients
{
    my ($public1, $secret1) = Crypt::Age::Keys->generate_keypair;
    my ($public2, $secret2) = Crypt::Age::Keys->generate_keypair;
    my $file_key = Crypt::Age::Primitives->generate_file_key;

    my $header = Crypt::Age::Header->create($file_key, [$public1, $public2]);

    is(scalar @{$header->stanzas}, 2, 'two stanzas for two recipients');

    my $unwrapped1 = $header->unwrap_file_key([$secret1]);
    is($unwrapped1, $file_key, 'first recipient can unwrap');

    my $unwrapped2 = $header->unwrap_file_key([$secret2]);
    is($unwrapped2, $file_key, 'second recipient can unwrap');
}

# A stanza body of exactly 64*n base64 characters requires an empty final
# line per the ABNF (final-line = *63base64char LF). PR #2 alone regressed
# this: it parsed the header text with split(/\n/, ...), which silently
# drops a trailing empty element, so the parser ran out of lines before
# seeing the required empty final line and died with "Invalid age stanza #1
# body". The filehandle-based line-by-line read restored correct handling.
# An X25519 body (32 bytes -> 43 base64 chars) never reaches this boundary,
# so this needs an unknown stanza type with a 48-byte body (64 base64
# chars) -- the parser doesn't validate stanza types, only structure.
{
    my $body = join '', map { chr($_ % 251) } 1 .. 48;
    my $body_b64 = Crypt::Age::Stanza::encode_base64_no_padding($body);
    is(length($body_b64), 64, 'fixture: body encodes to exactly 64 base64 chars');

    my $mac64 = Crypt::Age::Stanza::encode_base64_no_padding("\x00" x 32);
    my $str = join("\n",
        'age-encryption.org/v1',
        '-> stanza-test',
        $body_b64,
        '',            # required empty final line for a 64-char-multiple body
        "--- $mac64",
    ) . "\n";

    my $offset = 0;
    my $header = eval { Crypt::Age::Header->parse(\$str, \$offset) };
    is($@, '', 'header with an exact-64-char stanza body parses without dying');
    is(scalar @{$header->stanzas}, 1, 'one stanza parsed');
    is($header->stanzas->[0]->type, 'stanza-test', 'stanza type preserved');
    is(length($header->stanzas->[0]->body), 48, 'body decoded to the full 48 bytes');
    is($offset, length($str), 'offset lands at the end of the header');
}

# The header MAC must verify against the literal bytes that were read, not a
# re-serialization of the parsed stanzas (regression for commit 116444e):
# parse_from_fh passed the captured bytes under the constructor key 'bytes'
# while the attribute is '_bytes', so Moo silently dropped them and _bytes
# fell back to its lazy builder, which re-serializes the stanzas via
# Stanza::to_string instead of returning what was actually on the wire.
#
# This only shows up for a header our own writer cannot reproduce
# byte-for-byte: an extra unknown-type stanza whose body is exactly 64 base64
# characters, which requires an empty final line that Stanza::to_string
# omits (known gap, karr #3) -- the re-serialization comes out one byte
# short of the literal bytes. The MAC's correctness is not under test here
# (it's a fixed placeholder); only whether _bytes reflects the wire, so this
# needs no binary -- it's a literal-byte assertion per se.
{
    my ($public) = Crypt::Age::Keys->generate_keypair;
    my $file_key = Crypt::Age::Primitives->generate_file_key;
    my $stanza   = Crypt::Age::Stanza::X25519->wrap($file_key, $public);

    my $grease_body = join '', map { chr($_ % 251) } 1 .. 48;
    my $grease_body_b64 = Crypt::Age::Stanza::encode_base64_no_padding($grease_body);

    my $head_no_mac = join("\n",
        'age-encryption.org/v1',
        $stanza->to_string,
        '-> grease-test',
        $grease_body_b64,
        '',
        '---',
    );
    my $mac64 = Crypt::Age::Stanza::encode_base64_no_padding("\x00" x 32);
    my $str = "$head_no_mac $mac64\n";

    my $offset = 0;
    my $header = Crypt::Age::Header->parse(\$str, \$offset);

    is($header->_bytes, $head_no_mac,
        'captured header bytes match the literal input, not a re-serialization');
    is($offset, length($str), 'offset lands at the end of the crafted header');
}

done_testing;
