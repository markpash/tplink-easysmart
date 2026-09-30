#!/usr/bin/env perl
# Attempt to unlock RRCP register access by writing the RRCP security-mask
# registers 0x0201/0x0202 (RTL83xx "RRCP Security Mask Configuration").
#
# *** WRITES TO THE SWITCH ASIC ***  Only touches 0x0201/0x0202. Writes are not
# acknowledged. Read-only probes (GET) are used to detect whether access opens up.
# Needs root/CAP_NET_RAW.  Usage: rrcp_unlock.pl <iface> [switch-mac]
use strict; use warnings;
use IO::Select;
use Time::HiRes qw(time sleep);

use constant PF_PACKET => 17;
use constant SOCK_RAW  => 3;
use constant ETH_P_ALL => 0x0003;
sub htons { my $v = (shift) & 0xffff; return (($v & 0xff) << 8) | ($v >> 8); }
sub mac { my $m = shift; return "\xff" x 6 if $m eq 'bcast'; $m =~ s/[:.\-]//g; return pack("H*", $m); }

my $iface  = shift @ARGV // 'wlp0s20f3';
my $SWITCH = mac(shift @ARGV // '48:22:54:40:a8:d0');
my $BCAST  = mac('bcast');
my $ifidx = do { open(my $f,"<","/sys/class/net/$iface/ifindex") or die; my $i=<$f>; chomp $i; $i };
my $src   = mac(do { open(my $f,"<","/sys/class/net/$iface/address") or die; my $m=<$f>; chomp $m; $m });
printf "iface=%s switch=%s\n", $iface, unpack("H*",$SWITCH);

socket(my $sock, PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) or die "raw socket: $!";
my $sel = IO::Select->new($sock);

sub tx {
    my ($dst,$opcode,$auth,$reg,$data,$c1,$c2) = @_;
    my $pl = pack("C C n v V", 1, $opcode, $auth, $reg, $data) . pack("V V",$c1,$c2);
    my $f = $dst . $src . pack("n",0x8899) . $pl;
    $f .= "\0" x (60-length($f)) if length($f) < 60;
    my $sll = pack("v n V v C C a8", PF_PACKET, htons(0x8899), $ifidx, 0, 0, 6, $dst);
    send($sock, $f, 0, $sll) or die "send: $!";
}
sub drain {
    my ($wait) = @_; my $end = time + ($wait // 0.8); my @r;
    while (time < $end && $sel->can_read(0.1)) {
        my $b; next unless recv($sock, $b, 65535, 0);
        next unless length($b) >= 14 && unpack("n",substr($b,12,2)) == 0x8899;
        next unless substr($b,6,6) eq $SWITCH;
        push @r, $b;
    }
    return @r;
}
sub parse { my $p = substr($_[0],14);
    my ($pr,$oc)=unpack("CC",$p); my ($auth,$reg,$data)=unpack("n v V",substr($p,2,8));
    my ($c1,$c2)=unpack("V V",substr($p,10,8));
    return {pr=>$pr,oc=>$oc,rep=>($oc&0x80)?1:0,auth=>$auth,reg=>$reg,data=>$data,c1=>$c1,c2=>$c2}; }

sub hello {
    tx($BCAST,0,0x2379,0,0,0,0); my @r = drain(1.2);
    for my $b (@r){ my $q=parse($b);
        if ($q->{pr}==1 && ($q->{oc}&0x7f)==0 && $q->{rep}) {
            printf "  hello: OK (reg=0x%04x c1=0x%08x)\n",$q->{reg},$q->{c1}; return 1; } }
    print "  hello: NO reply\n"; return 0;
}
sub get {
    my ($reg) = @_;
    tx($BCAST,1,0x2379,$reg,0,0,0);
    tx($SWITCH,1,0x2379,$reg,0,0,0);
    my @r = drain(0.9);
    for my $b (@r){ my $q=parse($b);
        if ($q->{pr}==1 && ($q->{oc}&0x7f)==1 && $q->{rep}) {
            printf "  GET 0x%04x -> HIT data=0x%08x\n", $reg, $q->{data}; return 1; } }
    printf "  GET 0x%04x -> no reply\n", $reg; return 0;
}
sub wr {
    my ($reg,$data) = @_;
    printf "  SET 0x%04x = 0x%08x (x3 bcast + x3 unicast)\n", $reg, $data;
    for (1..3) { tx($BCAST,2,0x2379,$reg,$data,0,0); tx($SWITCH,2,0x2379,$reg,$data,0,0); }
    sleep(0.3);
}

print "[0] baseline\n"; hello(); my $hit0 = get(0x0206);

print "\n[1] write masks = 0x00000000 (clear)\n";
wr(0x0201,0); wr(0x0202,0); sleep(0.5);
hello();
get(0x0206); get(0x0200); get(0x0201); get(0x0202); get(0x0207); get(0x0209);

print "\n[2] write masks = 0xffffffff\n";
wr(0x0201,0xffffffff); wr(0x0202,0xffffffff); sleep(0.5);
hello();
get(0x0000); get(0x0001); get(0x0206); get(0x0200);

print "\n[3] restore masks = 0x00000000\n";
wr(0x0201,0); wr(0x0202,0); sleep(0.5);
hello(); get(0x0206);

print "\ndone (baseline get reply: ".($hit0?"yes":"no").")\n";
