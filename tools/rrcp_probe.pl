#!/usr/bin/env perl
# RRCP probe: discover whether GET (register read) works on the switch, and which
# cookie/destination combination it needs. Read-only (opcode 0 hello, 1 get).
# Needs root/CAP_NET_RAW.  Usage: rrcp_probe.pl <iface> [switch-mac]
use strict; use warnings;
use IO::Select;

use constant PF_PACKET => 17;
use constant SOCK_RAW  => 3;
use constant ETH_P_ALL => 0x0003;
sub htons { my $v = (shift) & 0xffff; return (($v & 0xff) << 8) | ($v >> 8); }
sub mac { my $m = shift; return "\xff" x 6 if $m eq 'bcast'; $m =~ s/[:.\-]//g; return pack("H*", $m); }

my $iface  = shift @ARGV // 'wlp0s20f3';
my $SWITCH = mac(shift @ARGV // '48:22:54:40:a8:d0');
my $BCAST  = mac('bcast');
my $ifidx = do { open(my $f,"<","/sys/class/net/$iface/ifindex") or die "no iface $iface\n"; my $i=<$f>; chomp $i; $i };
my $src   = mac(do { open(my $f,"<","/sys/class/net/$iface/address") or die; my $m=<$f>; chomp $m; $m });
printf "iface=%s our=%s switch=%s\n", $iface, unpack("H*",$src), unpack("H*",$SWITCH);

socket(my $sock, PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) or die "raw socket: $!";

sub xchg {
    my ($dst,$proto,$opcode,$auth,$reg,$data,$c1,$c2,$wait) = @_;
    my $payload = pack("C C n v V", $proto,$opcode,$auth,$reg,$data) . pack("V V",$c1,$c2);
    my $frame = $dst . $src . pack("n",0x8899) . $payload;
    $frame .= "\0" x (60-length($frame)) if length($frame) < 60;
    my $sll = pack("v n V v C C a8", PF_PACKET, htons(0x8899), $ifidx, 0, 0, 6, $dst);
    send($sock, $frame, 0, $sll) or die "send: $!";
    my $sel = IO::Select->new($sock); my $end = time + ($wait // 1.2); my @r;
    while (time < $end && $sel->can_read(0.2)) {
        my $buf; next unless recv($sock, $buf, 65535, 0);
        next unless length($buf) >= 14 && unpack("n", substr($buf,12,2)) == 0x8899;
        next unless substr($buf,6,6) eq $SWITCH;         # only frames from the switch
        push @r, $buf;
    }
    return @r;
}
sub parse {
    my ($p) = @_; $p = substr($p,14);
    my ($pr,$oc) = unpack("CC",$p);
    my ($auth,$reg,$data) = unpack("n v V", substr($p,2,8));
    my ($c1,$c2) = unpack("V V", substr($p,10,8));
    my ($dl,$ul) = (ord(substr($p,18,1)), ord(substr($p,19,1)));
    my $ulmac = unpack("H*", substr($p,20,6));
    my $vend  = unpack("N", substr($p,26,4));
    my $chip  = unpack("n", substr($p,30,2));
    return {pr=>$pr,oc=>$oc,rep=>($oc&0x80)?1:0,auth=>$auth,reg=>$reg,data=>$data,c1=>$c1,c2=>$c2,
            dl=>$dl,ul=>$ul,ulmac=>$ulmac,vend=>$vend,chip=>$chip};
}

my $R1 = 0x11223344; my $R2 = 0x55667788;

sub show { my (@r)=@_; if(!@r){ print "   -> (no reply from switch)\n"; return; }
    for my $b (@r){ my $q=parse($b);
        printf "   <- proto=%d opcode=0x%02x reply=%d auth=0x%04x reg=0x%04x data=0x%08x c1=0x%08x c2=0x%08x\n",
            $q->{pr},$q->{oc},$q->{rep},$q->{auth},$q->{reg},$q->{data},$q->{c1},$q->{c2};
        if ($q->{pr}==1 && ($q->{oc}&0x7f)==0 && $q->{rep}) {
            printf "      HELLO downlink=%d uplink=%d ul_mac=%s vendor=0x%08x chip=0x%04x\n",
                $q->{dl},$q->{ul},$q->{ulmac},$q->{vend},$q->{chip};
        }
    }
}

print "\n[1] hello (cookie 0) bcast\n";
show(xchg($BCAST,1,0,0x2379,0,0,0,0,1.5));
print "[2] hello (cookie 0x11223344/0x55667788) bcast\n";
show(xchg($BCAST,1,0,0x2379,0,0,$R1,$R2,1.5));

my @regs = (0x0000,0x0002,0x0007,0x0200,0x0206,0x0207,0x0208,0x0201,0x0100);
for my $dst (["bcast",$BCAST],["switch",$SWITCH]) {
  for my $cook (["0",0,0],["rand",$R1,$R2]) {
    printf "\n--- GET reg sweep dst=%s cookie=%s ---\n", $dst->[0], $cook->[0];
    for my $reg (@regs) {
        printf "[get] dst=%-6s reg=0x%04x c=%s\n", $dst->[0], $reg, $cook->[0];
        show(xchg($dst->[1],1,1,0x2379,$reg,0,$cook->[1],$cook->[2],0.8));
    }
  }
}
print "\ndone.\n";

# [3] reuse the cookie from a fresh hello reply
my @h = xchg($BCAST,1,0,0x2379,0,0,0,0,1.5);
if (@h) {
    my $q = parse($h[0]);
    printf "\n[3] hello reply: reg=0x%04x c1=0x%08x c2=0x%08x -> reuse as GET cookie\n", $q->{reg},$q->{c1},$q->{c2};
    for my $reg (0x0200,0x0206,0x0207,0x0000,0x0201,0x0202) {
        for my $d ([$BCAST,"bcast"],[$SWITCH,"switch"]) {
            printf "[get] dst=%-6s reg=0x%04x hello-cookie\n", $d->[1], $reg;
            show(xchg($d->[0],1,1,0x2379,$reg,0,$q->{c1},$q->{c2},0.8));
        }
    }
} else {
    print "\n[3] hello produced no reply (unexpected)\n";
}

