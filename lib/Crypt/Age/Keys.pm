package Crypt::Age::Keys;
# ABSTRACT: Key generation and Bech32 encoding for age encryption

use Moo;
use Carp qw(croak);
use Crypt::PK::X25519;
use namespace::clean;

# Bech32 character set
my $BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
my %BECH32_CHAR_TO_VAL = map { substr($BECH32_CHARSET, $_, 1) => $_ } 0..31;

# Human-readable parts
my $HRP_PUBLIC  = 'age';
my $HRP_SECRET  = 'age-secret-key-';

sub generate_keypair {
    my ($class) = @_;

    my $pk = Crypt::PK::X25519->new;
    $pk->generate_key;

    my $secret_bytes = $pk->export_key_raw('private');
    my $public_bytes = $pk->export_key_raw('public');

    my $public_key = $class->encode_public_key($public_bytes);
    my $secret_key = $class->encode_secret_key($secret_bytes);

    return ($public_key, $secret_key);
}

sub encode_public_key {
    my ($class, $bytes) = @_;
    croak "Public key must be 32 bytes" unless length($bytes) == 32;
    return $class->bech32_encode($HRP_PUBLIC, $bytes);
}

sub decode_public_key {
    my ($class, $encoded) = @_;
    my ($hrp, $bytes) = $class->bech32_decode($encoded);
    croak "Invalid public key HRP: expected '$HRP_PUBLIC', got '$hrp'"
        unless lc($hrp) eq $HRP_PUBLIC;
    croak "Invalid public key length" unless length($bytes) == 32;
    return $bytes;
}

sub encode_secret_key {
    my ($class, $bytes) = @_;
    croak "Secret key must be 32 bytes" unless length($bytes) == 32;
    return uc($class->bech32_encode($HRP_SECRET, $bytes));
}

sub decode_secret_key {
    my ($class, $encoded) = @_;
    my ($hrp, $bytes) = $class->bech32_decode($encoded);
    croak "Invalid secret key HRP: expected '$HRP_SECRET', got '$hrp'"
        unless lc($hrp) eq $HRP_SECRET;
    croak "Invalid secret key length" unless length($bytes) == 32;
    return $bytes;
}

sub public_key_from_secret {
    my ($class, $secret_key) = @_;
    my $secret_bytes = $class->decode_secret_key($secret_key);
    my $pk = Crypt::PK::X25519->new;
    $pk->import_key_raw($secret_bytes, 'private');
    my $public_bytes = $pk->export_key_raw('public');
    return $class->encode_public_key($public_bytes);
}

# Bech32 implementation (BIP-173)

sub bech32_polymod {
    my ($values) = @_;
    my @GEN = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3);
    my $chk = 1;
    for my $v (@$values) {
        my $b = $chk >> 25;
        $chk = (($chk & 0x1ffffff) << 5) ^ $v;
        for my $i (0..4) {
            $chk ^= (($b >> $i) & 1) ? $GEN[$i] : 0;
        }
    }
    return $chk;
}

sub bech32_hrp_expand {
    my ($hrp) = @_;
    my @result;
    for my $c (split //, $hrp) {
        push @result, ord($c) >> 5;
    }
    push @result, 0;
    for my $c (split //, $hrp) {
        push @result, ord($c) & 31;
    }
    return \@result;
}

sub bech32_create_checksum {
    my ($hrp, $data) = @_;
    my @values = (@{bech32_hrp_expand($hrp)}, @$data, 0, 0, 0, 0, 0, 0);
    my $polymod = bech32_polymod(\@values) ^ 1;
    my @checksum;
    for my $i (0..5) {
        push @checksum, ($polymod >> (5 * (5 - $i))) & 31;
    }
    return \@checksum;
}

sub bech32_verify_checksum {
    my ($hrp, $data) = @_;
    return bech32_polymod([@{bech32_hrp_expand($hrp)}, @$data]) == 1;
}

sub bech32_encode {
    my ($class, $hrp, $bytes) = @_;

    # Convert 8-bit bytes to 5-bit groups
    my $data = $class->_convert_bits([unpack('C*', $bytes)], 8, 5, 1);

    my $checksum = bech32_create_checksum($hrp, $data);
    my @combined = (@$data, @$checksum);

    my $result = $hrp . '1';
    for my $d (@combined) {
        $result .= substr($BECH32_CHARSET, $d, 1);
    }

    return $result;
}

sub bech32_decode {
    my ($class, $str) = @_;

    # Find separator
    my $sep_pos = rindex($str, '1');
    croak "Invalid bech32: no separator" if $sep_pos < 1;
    croak "Invalid bech32: empty data" if $sep_pos + 1 >= length($str);

    my $hrp = substr($str, 0, $sep_pos);
    my $data_part = lc(substr($str, $sep_pos + 1));

    # Decode data part
    my @data;
    for my $c (split //, $data_part) {
        croak "Invalid bech32 character: $c" unless exists $BECH32_CHAR_TO_VAL{$c};
        push @data, $BECH32_CHAR_TO_VAL{$c};
    }

    croak "Invalid bech32 checksum"
        unless bech32_verify_checksum(lc($hrp), \@data);

    # Remove checksum (last 6 values)
    splice(@data, -6);

    # Convert 5-bit groups back to 8-bit bytes
    my $bytes = $class->_convert_bits(\@data, 5, 8, 0);

    return ($hrp, pack('C*', @$bytes));
}

sub _convert_bits {
    my ($class, $data, $from_bits, $to_bits, $pad) = @_;

    my $acc = 0;
    my $bits = 0;
    my @result;
    my $maxv = (1 << $to_bits) - 1;

    for my $v (@$data) {
        $acc = ($acc << $from_bits) | $v;
        $bits += $from_bits;
        while ($bits >= $to_bits) {
            $bits -= $to_bits;
            push @result, ($acc >> $bits) & $maxv;
        }
    }

    if ($pad) {
        if ($bits > 0) {
            push @result, ($acc << ($to_bits - $bits)) & $maxv;
        }
    } else {
        croak "Invalid padding" if $bits >= $from_bits;
        croak "Non-zero padding" if (($acc << ($to_bits - $bits)) & $maxv);
    }

    return \@result;
}

1;
