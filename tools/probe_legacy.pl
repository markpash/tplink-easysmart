use strict; use warnings;
use IO::Socket::INET;
use IO::Select;

my @KEY = (191,155,227,202,99,162,79,104,49,18,190,164,30,76,189,131,23,52,86,106,207,125,126,169,196,28,172,58,188,132,160,3,36,120,144,168,12,231,116,44,41,97,108,213,42,198,32,148,218,107,247,112,204,14,66,68,91,224,206,235,33,130,203,178,1,134,199,78,249,123,7,145,73,208,209,100,74,115,72,118,8,22,243,147,64,96,5,87,60,113,233,152,31,219,143,174,232,153,245,158,254,70,170,75,77,215,211,59,71,133,214,157,151,6,46,81,94,136,166,210,4,43,241,29,223,176,67,63,186,137,129,40,248,255,55,15,62,183,222,105,236,197,127,54,179,194,229,185,37,90,237,184,25,156,173,26,187,220,2,225,0,240,50,251,212,253,167,17,193,205,177,21,181,246,82,226,38,101,163,182,242,92,20,11,95,13,230,16,121,124,109,195,117,39,98,239,84,56,139,161,47,201,51,135,250,10,19,150,45,111,27,24,142,80,85,83,234,138,216,57,93,65,154,141,122,34,140,128,238,88,89,9,146,171,149,53,102,61,114,69,217,175,103,228,35,180,252,200,192,165,159,221,244,110,119,48);
sub rc4 { my ($in)=@_; my @d=unpack("C*",$in); my @s=@KEY; my $j=0;
  for my $k (0..$#d){ my $i=($k+1)&255; $j=($j+$s[$i])&255; ($s[$i],$s[$j])=($s[$j],$s[$i]); $d[$k]^=$s[($s[$i]+$s[$j])&255]; }
  return pack("C*",@d); }
my $HOST_MAC = "\x00\x11\x22\x33\x44\x55";
my $SW_MAC   = "\x48\x22\x54\x40\xa8\xd0";
my $seq = int(rand(1000));
sub build { my ($op,$payload,$token,$swmac)=@_; $token//=0; $swmac//=("\x00"x6);
  my $len=32+length($payload)+4;
  return pack("CC",1,$op).$swmac.$HOST_MAC.pack("n",$seq).pack("N",0)
    .pack("n",$len).pack("n",0).pack("n",0).pack("n",$token).pack("N",0).$payload."\xff\xff\x00\x00"; }
sub tlv { my ($t,$v)=@_; return pack("nn",$t,length($v)).$v; }
sub parse { my ($dec)=@_; my $p=substr($dec,32); my @out;
  while (length($p)>4){ my ($t,$l)=unpack("nn",substr($p,0,4)); last if $t==0xffff;
    my $v=substr($p,4,$l); push @out, [$t,$l,unpack("H*",$v)]; $p=substr($p,4+$l); }
  return @out; }

my $rs = IO::Socket::INET->new(LocalPort=>29809,Proto=>'udp',Broadcast=>1,ReuseAddr=>1) or die $!;
my $ss = IO::Socket::INET->new(Proto=>'udp',Broadcast=>1) or die $!;
my $sel = IO::Select->new($rs);
my $TOKEN = 0;

sub query {
  my ($op,$payload,$label)=@_;
  $seq++;
  $ss->send(rc4(build($op,$payload,$TOKEN,$SW_MAC)),0,pack_sockaddr_in(29808,inet_aton("10.0.0.106")));
  if ($sel->can_read(3)) {
    my $buf; my $a=$rs->recv($buf,4096,0); my $dec=rc4($buf);
    my ($ver,$rop)=unpack("CC",$dec);
    my $err = unpack("N",substr($dec,16,4));
    $TOKEN = unpack("n",substr($dec,26,2));
    my @tlvs = parse($dec);
    printf "[%s] op=%d err=%d token=%d tlvs=%d\n",$label,$rop,$err,$TOKEN,scalar(@tlvs);
    printf "    type=%d len=%d val=%s\n",$_->[0],$_->[1],$_->[2] for @tlvs;
    return @tlvs;
  }
  printf "[%s] no reply\n",$label;
  return;
}

query(1, tlv(2305,""), "get_token");
query(3, tlv(512,"admin\0").tlv(514,"admin1\0"), "login");
query(1, tlv(1,""), "get_type");
query(1, tlv(16384,""), "get_stats");
query(1, tlv(4096,""), "get_ports");
