use strict; use warnings;
use IO::Socket::INET;
use IO::Select;
use Errno qw(ECONNREFUSED EAGAIN EWOULDBLOCK);

my $host = "10.0.0.106";
my ($lo,$hi) = @ARGV; $lo//=1; $hi//=65535;

my %sock; my $sel = IO::Select->new();
for my $p ($lo..$hi) {
    my $s = IO::Socket::INET->new(Proto=>'udp', PeerAddr=>$host, PeerPort=>$p);
    next unless $s;
    $s->blocking(0);
    my $sent = $s->send("\x00");
    $sock{$p} = $s;
    $sel->add($s);
}
print "probing ", scalar(keys %sock), " udp ports on $host ...\n";
my $deadline = time + 3;
my %status;
while ($deadline > time) {
    my @ready = $sel->can_read($deadline - time);
    last unless @ready;
    for my $s (@ready) {
        my %p; $p{peerport} = (sockaddr_in($s->peername))[0];
        my $buf; my $r = $s->recv($buf, 512);
        if (!defined $r) {
            if ($!{ECONNREFUSED} || $! == ECONNREFUSED) { $status{$p{peerport}} = 'closed'; }
            elsif ($!{EAGAIN} || $!{EWOULDBLOCK}) { next; }
            else { $status{$p{peerport}} = "err:$!"; }
        } else {
            $status{$p{peerport}} = 'OPEN:'.unpack("H*",$buf);
        }
        $sel->remove($s);
    }
}
# any not ready => open|filtered (or ICMP suppressed)
my @silent = grep { !exists $status{$_} } sort { $a <=> $b } keys %sock;
print "== responded/errored ==\n";
printf "  %5d  %s\n", $_, $status{$_} for sort {$a<=>$b} keys %status;
print "== silent (open|filtered) ==\n";
print "  @silent\n";
