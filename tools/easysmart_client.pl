#!/usr/bin/env perl
# Standalone TP-Link Easy Smart client implementing the legacy ESCP + the 2023
# RSA/session-key "upgraded management protocol". No dependency on the official utility.
use strict; use warnings;
use Math::BigInt;
use IO::Socket::INET;
use IO::Select;

my $SW   = $ARGV[0] // "10.0.0.106";
my $USER = $ARGV[1] // "admin";
my $PASS = $ARGV[2] // "admin1";
my $SWPORT = 29808;
my $LOCAL  = 29809;

# ---- static RC4 key table (256 bytes) : final S-box used by of.Code ----
my @SKEYS = (191,155,227,202,99,162,79,104,49,18,190,164,30,76,189,131,23,52,86,106,207,125,126,169,196,28,172,58,188,132,160,3,36,120,144,168,12,231,116,44,41,97,108,213,42,198,32,148,218,107,247,112,204,14,66,68,91,224,206,235,33,130,203,178,1,134,199,78,249,123,7,145,73,208,209,100,74,115,72,118,8,22,243,147,64,96,5,87,60,113,233,152,31,219,143,174,232,153,245,158,254,70,170,75,77,215,211,59,71,133,214,157,151,6,46,81,94,136,166,210,4,43,241,29,223,176,67,63,186,137,129,40,248,255,55,15,62,183,222,105,236,197,127,54,179,194,229,185,37,90,237,184,25,156,173,26,187,220,2,225,0,240,50,251,212,253,167,17,193,205,177,21,181,246,82,226,38,101,163,182,242,92,20,11,95,13,230,16,121,124,109,195,117,39,98,239,84,56,139,161,47,201,51,135,250,10,19,150,45,111,27,24,142,80,85,83,234,138,216,57,93,65,154,141,122,34,140,128,238,88,89,9,146,171,149,53,102,61,114,69,217,175,103,228,35,180,252,200,192,165,159,221,244,110,119,48);

# ---- small RSA public key used when From.bw()==false (fw 1.0.0) ----
my $N = Math::BigInt->new("0xB3FAB9D6646D4EBF");
my $E = Math::BigInt->new(65537);

sub rc4_static { my ($in)=@_; my @d=unpack("C*",$in); my @s=@SKEYS; my ($i,$j)=(0,0);
  for my $k (0..$#d){ $i=($i+1)&255; $j=($j+$s[$i])&255; @s[$i,$j]=@s[$j,$i];
    $d[$k]^=$s[($s[$i]+$s[$j])&255]; } return pack("C*",@d); }

sub rc4_session { my ($in,$key)=@_; my @s=(0..7); my @op=map { ord } split //,$key; my $j=0;
  for my $n (0..7){ $j=($j+$s[$n]+$op[$n])%8; @s[$n,$j]=@s[$j,$n]; }
  my @d=unpack("C*",$in); my ($i2,$j2)=(0,0);
  for my $k (0..$#d){ $i2=($i2+1)%8; $j2=($j2+$s[$i2])%8; @s[$i2,$j2]=@s[$j2,$i2];
    $d[$k]^=$s[($s[$i2]+$s[$j2])%8]; } return pack("C*",@d); }

sub rsa_encrypt_sessionkey { my ($key)=@_;
  # m = little-endian(key bytes)
  my @b = reverse unpack("C*",$key); my $hex="0x"; $hex.=sprintf("%02x",$_) for @b;
  my $m = Math::BigInt->new($hex);
  my $c = $m->copy->bmodpow($E,$N);
  my $chex = $c->as_hex; $chex =~ s/^0x//; $chex = "0$chex" if length($chex)%2;
  my @cle = reverse split //, $chex; # not used; build bytes:
  my $bytes = pack("H*", $chex); my @cb = reverse unpack("C*",$bytes); # little-endian
  @cb = (@cb, (0) x (8-@cb)) if @cb<8; @cb=@cb[0..7] if @cb>8;
  return pack("CC",0,4).pack("C*",@cb);   # [0][limbcount=4][c LE 8 bytes]
}

# ---- framing ----
my $seq = int(rand(1000)); my $TOKEN=0; my $SWMAC="\x00"x6;
my $HOSTMAC = "\x00\x11\x22\x33\x44\x55";
sub tlv { my ($t,$v)=@_; return pack("nn",$t,length($v)).$v; }
sub mkpkt { my ($op,$payload)=@_;
  my $len = 32+length($payload)+4;
  return pack("CC",1,$op).$SWMAC.$HOSTMAC.pack("n",$seq++).pack("N",0)
    .pack("n",$len).pack("n",0).pack("n",0).pack("n",$TOKEN).pack("N",0).$payload."\xff\xff\x00\x00"; }

my $rs=IO::Socket::INET->new(LocalPort=>$LOCAL,Proto=>"udp",Broadcast=>1,ReuseAddr=>1) or die $!;
my $ss=IO::Socket::INET->new(Proto=>"udp",Broadcast=>1) or die $!;
my $sel=IO::Select->new($rs);
my $SESSKEY=""; my $USESESSION=0;

sub send_pkt { my ($op,$payload,$session)=@_;
  my $pkt = mkpkt($op,$payload);
  my $enc = $session ? rc4_session($pkt,$SESSKEY) : rc4_static($pkt);
  printf ">>> %s op=%d len=%d\n", ($session?"SESSION":"STATIC"), $op, length($pkt);
  printf "    plain: %s\n", unpack("H*",$pkt);
  printf "    enc  : %s\n", unpack("H*",$enc);
  $ss->send($enc,0,pack_sockaddr_in($SWPORT,inet_aton($SW)));
}
sub recv_pkt {
  return undef unless $sel->can_read(2.5);
  my $buf; my $a=$rs->recv($buf,4096,0); my ($port,$ip)=sockaddr_in($a);
  return undef if inet_ntoa($ip) ne $SW;
  my $dec;
  my $st=rc4_static($buf);
  if (length($st)>=2 && ord(substr($st,0,1))==1 && ord(substr($st,1,1))<5) { $dec=$st; print "    [static]\n"; }
  else { $dec=rc4_session($buf,$SESSKEY); print "    [session]\n"; }
  my ($ver,$op)=unpack("CC",$dec);
  my $err=unpack("N",substr($dec,16,4));
  my $tok=unpack("n",substr($dec,26,2));
  my $mac=unpack("H*",substr($dec,2,6));
  printf "<<< from %s op=%d err=%d token=%d swmac=%s raw=%s\n", inet_ntoa($ip),$op,$err,$tok,$mac,unpack("H*",$dec);
  if ($op==2||$op==4){ $TOKEN=$tok; $SWMAC=substr($dec,2,6); }
  # parse TLVs
  my $p=substr($dec,32);
  while (length($p)>4){ my ($t,$l)=unpack("nn",substr($p,0,4)); last if $t==0xffff; last if length($p)<4+$l;
    printf "    TLV %d len=%d %s\n",$t,$l,unpack("H*",substr($p,4,$l)); $p=substr($p,4+$l); }
  return { dec=>$dec, op=>$op, err=>$err };
}

print "=== discovering $SW ===\n";
for my $try (1..6){ send_pkt(0,"",0); my $r=recv_pkt(); last if $SWMAC ne "\x00"x6; sleep(1); }
printf "SWMAC=%s\n", unpack("H*",$SWMAC);

print "\n=== GET get_token_id (static) ===\n";
my $r;
for (1..3){ send_pkt(1,tlv(2305,""),0); $r=recv_pkt(); last if $r; sleep(1); }

print "\n=== RSA session-key exchange (static) ===\n";
$SESSKEY = (join "", map { ("A".."Z","a".."z",0..9)[int(rand(62))] } 1..8);
my $rsa = rsa_encrypt_sessionkey($SESSKEY);
print "session key = '$SESSKEY'  rsa tlv value = ".unpack("H*",$rsa)."\n";
send_pkt(3,tlv(528,$rsa),0); $r=recv_pkt();
if ($r && $r->{err}==4098){ print "RSA accepted (4098); switching to session key\n"; $USESESSION=1; }
else { print "RSA not accepted; staying on legacy static key\n"; }

print "\n=== GET get_token_id (session) ===\n";
for (1..3){ send_pkt(1,tlv(2305,""),$USESESSION); $r=recv_pkt(); last if $r; sleep(1); }

print "\n=== LOGIN (session) ===\n";
my $login = tlv(512,$USER."\0").tlv(514,$PASS."\0");
send_pkt(3,$login,$USESESSION); $r=recv_pkt();
printf "login result: op=%s err=%s\n", $r?$r->{op}:"-", $r?$r->{err}:"-";

print "\n=== GET port stats type=16384 (session) ===\n";
send_pkt(1,tlv(16384,""),$USESESSION); $r=recv_pkt();
printf "stats result: op=%s err=%s\n", $r?$r->{op}:"-", $r?$r->{err}:"-";

print "\n=== GET ports type=4096 (session) ===\n";
send_pkt(1,tlv(4096,""),$USESESSION); $r=recv_pkt();
printf "ports result: op=%s err=%s\n", $r?$r->{op}:"-", $r?$r->{err}:"-";
print "\n=== done ===\n";
