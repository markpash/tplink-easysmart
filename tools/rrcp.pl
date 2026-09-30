#!/usr/bin/env perl
# Minimal RRCP (Realtek Remote Control Protocol) tool.
# Usage: rrcp.pl <iface> hello
#        rrcp.pl <iface> get <reghex>
#        rrcp.pl <iface> set <reghex> <valhex>
use strict; use warnings;
use IO::Select;

use constant PF_PACKET => 17;
use constant SOCK_RAW  => 3;
use constant ETH_P_ALL => 0x0003;

my $iface = shift @ARGV or die "usage: $0 iface hello|get|set ...\n";
my $cmd   = shift @ARGV // "hello";
my $ifidx = do { open(my $f,"<","/sys/class/net/$iface/ifindex") or die "no such interface $iface\n"; my $i=<$f>; chomp $i; $i };

# get our interface MAC
my $ours = do { open(my $fh,"<","/sys/class/net/$iface/address") or die $!; my $m=<$fh>; chomp $m; $m; };
my $src = pack("H*", join("", split(/:/,$ours)));

sub mac2 { my $m=shift; return "\xff"x6 if $m eq "bcast"; $m=~s/[:.\-]//g; return pack("H*",$m); }

my $dst = mac2("bcast");

my ($proto,$opcode,$auth,$reg,$data) = (1,0,0x2379,0,0);
if ($cmd eq "hello") { $opcode = 0x00; }
elsif ($cmd eq "get") { $opcode = 0x01; $reg = hex(shift @ARGV // "0x0206"); }
elsif ($cmd eq "set") { $opcode = 0x02; $reg = hex(shift @ARGV // "0x0206"); $data = hex(shift @ARGV // "0"); }

# RRCP payload: proto(1) opcode(1) auth(BE16) regaddr(LE16) regdata(LE32) cookie1(4) cookie2(4)
my $payload = pack("C C n v V", $proto, $opcode, $auth, $reg, $data) . ("\x00" x 8);
my $frame = $dst . $src . pack("n", 0x8899) . $payload;
$frame .= "\x00" x (60 - length($frame)) if length($frame) < 60;

# AF_PACKET wants the protocol as an integer in network byte order.
sub htons { my $v = (shift) & 0xffff; return (($v & 0xff) << 8) | ($v >> 8); }
my $ETH_8899 = 0x8899;
my $sock;
socket($sock, PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) or die "raw socket: $!";
my $sll = pack("v n V v C C a8", PF_PACKET, htons($ETH_8899), $ifidx, 0, 0, 6, mac2("bcast"));
send($sock, $frame, 0, $sll) or die "send: $!";
printf "sent %s opcode=0x%02x reg=0x%04x data=0x%08x dst=%s on %s\n",
  $cmd, $opcode, $reg, $data, unpack("H*",$dst), $iface;

my $sel = IO::Select->new($sock);
my $end = time + 3;
while (time < $end && $sel->can_read(0.5)) {
  my $buf; my $from;
    if (recv($sock, $buf, 65535, 0)) {
    next unless length($buf) >= 14;
    my $et = unpack("n", substr($buf,12,2));
    next unless $et == 0x8899;
    printf "RAW (%d bytes): %s\n", length($buf), unpack("H*", $buf);
    my $p = substr($buf,14);
    my ($pr,$oc)=unpack("CC",$p);
    my ($reg,$data)=unpack("v V", substr($p,4,6));
    printf "REPLY proto=%d opcode=0x%02x reply=%d reg=0x%04x data=0x%08x\n",
      $pr, $oc & 0x7f, ($oc & 0x80)?1:0, $reg, $data;
    if (($oc & 0x7f)==0 && ($oc & 0x80)) {
      # hello reply: downlink/up/ul_mac/vendor/chip
      my ($dl,$ul)= (ord(substr($p,18,1)), ord(substr($p,19,1)));
      my $ulmac = unpack("H*", substr($p,20,6));
      my $vend = unpack("N", substr($p,26,4));
      my $chip = unpack("n", substr($p,30,2));
      print "  HELLO_REPLY downlink=$dl uplink=$ul ul_mac=$ulmac vendor=0x".sprintf("%08x",$vend)." chip=0x".sprintf("%04x",$chip)."\n";
    }
  }
}
