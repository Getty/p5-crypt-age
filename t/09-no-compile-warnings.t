#!/usr/bin/env perl
# Every module of the distribution must compile without a single warning, on
# every perl it supports. Older perls warn about constructs newer ones accept
# silently (perl 5.16 to 5.20: 'Ambiguous use of -TAG_SIZE resolved as
# -&TAG_SIZE()'), and a warning at load time lands on every caller's stderr.
use strict;
use warnings;
use Test::More;
use File::Find ();
use File::Spec ();

my @modules;
File::Find::find(
    {
        no_chdir => 1,
        wanted   => sub {
            return unless /\.pm\z/;
            my $rel = File::Spec->abs2rel($_, 'lib');
            $rel =~ s/\.pm\z//;
            push @modules, join '::', File::Spec->splitdir($rel);
        },
    },
    'lib',
);
@modules = sort @modules;

ok(scalar(@modules) >= 6, 'found the modules under lib/') or diag("@modules");

my @inc = map { "-I$_" } grep { !ref } @INC;

for my $module (@modules) {
    # Any warning raised while the module compiles ends the child with
    # status 3 and shows up in its output.
    my $code = 'BEGIN { $SIG{__WARN__} = sub { print STDERR "WARNING: @_"; exit 3 } } '
        . "require $module; print qq{loaded\\n}";
    my $out = qx{"$^X" -w @inc -e '$code' 2>&1};
    my $status = $? >> 8;
    is($out, "loaded\n", "$module compiles without any warning")
        or diag("exit status $status");
}

done_testing;
