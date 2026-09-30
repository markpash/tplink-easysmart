#!/usr/bin/env perl
# Helpers for the HTTP/CGI reverse-engineering (see docs/HTTP_SERVER_RE.md).
# Maps between .bin / payload / flash / banked-CPU addresses and dumps regions.
#
#   re_map.pl pay2flash <off> [--seg b]
#   re_map.pl flash2pay <off>
#   re_map.pl flash2cpu <off> [bank]      # fixed-region rule flash=bank*0x10000+0x4000+adj
#   re_map.pl dump-flash <off> <len>      # hex+ascii from the flash dump
#   re_map.pl dump-bin   <off> <len>      # hex+ascii from the .bin
#   re_map.pl str <string>                # occurrences in flash and .bin
use strict; use warnings;

my $FLASH = "dumps/fixed.bin";
my $BIN   = "firmware/stock_6.0_1.0.0_20230218.bin";
my $SEG_A = 0x2E0C;
sub load { my ($f)=@_; open(my $h,"<:raw",$f) or die "$f: $!"; local $/; my $d=<$h>; close $h; return $d; }
sub num  { my $s = shift; $s =~ s/^0x//i; return hex($s); }
sub hx   { my $s = shift; $s =~ s/(.)/sprintf("%02x ",ord($1))/ge; return $s; }

my ($cmd,@a) = @ARGV;
$cmd //= 'help';
if ($cmd eq 'pay2flash') {
    my $p = num($a[0]); my $segB = grep { $_ eq '--seg' } @a;
    my $f = ($p < $SEG_A) ? 0x1002 + $p : 0x1BE0E + ($p - $SEG_A);
    printf "payload 0x%X -> flash 0x%X (%s)\n", $p, $f, ($p<$SEG_A?"segment A":"segment B");
} elsif ($cmd eq 'flash2pay') {
    my $f = num($a[0]);
    my $p = ($f >= 0x1002 && $f < 0x3E0E) ? $f - 0x1002
          : ($f >= 0x1BE0E)              ? $SEG_A + ($f - 0x1BE0E)
          : undef;
    defined $p ? printf "flash 0x%X -> payload 0x%X\n",$f,$p
               : print "flash 0x$f is outside the app segments\n";
} elsif ($cmd eq 'flash2cpu') {
    my $f = num($a[0]); my $bank = defined $a[1] ? num($a[1]) : (($f-0x4000)>>16);
    my $adj = ($f - 0x4000) - $bank*0x10000;
    printf "flash 0x%X -> bank %d cpu_addr 0x%04X (= (flash-0x4000) mod 0x10000)\n",$f,$bank,$adj;
} elsif ($cmd eq 'dump-flash' || $cmd eq 'dump-bin') {
    my $d = load($cmd eq 'dump-flash' ? $FLASH : $BIN);
    my $o = num($a[0]); my $n = num($a[1] // '64');
    for (my $i=0; $i<$n; $i+=16) {
        my $s = substr($d,$o+$i,16);
        my $as = $s; $as =~ s/([^\x20-\x7e])/./g;
        printf "%06X  %-48s %s\n",$o+$i,hx($s),$as;
    }
} elsif ($cmd eq 'str') {
    my $s = $a[0] // die "need string\n";
    for my $pair ([$BIN,'.bin'],[$FLASH,'flash']) {
        my ($f,$nm)=@$pair; my $d=load($f); my $p=0; my @h;
        while(($p=index($d,$s,$p))>=0){ push @h,sprintf("0x%X",$p); $p++; last if @h>=12; }
        printf "%-5s %s\n",$nm,(@h?join(", ",@h):"-");
    }
} else {
    print "commands: pay2flash flash2pay flash2cpu dump-flash dump-bin str\n";
}
