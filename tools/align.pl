use strict; use warnings;
# Align bin (update file) to flash (rendered image) to recover the block layout.
my ($binf,$flf)=@ARGV;
my $B; { open(my $h,"<:raw",$binf)or die "$binf: $!"; local $/; $B=<$h>; }
my $F; { open(my $h,"<:raw",$flf)or die "$flf: $!"; local $/; $F=<$h>; }
my $lb=length($B); my $lf=length($F);
my $STEP=0x1000;
my $WIN=0x40000;

# initial match: unique 64-byte needle at offset 0
my $p0=index($F,substr($B,0,64));
die "no initial match\n" if $p0<0;
printf "bin[0] -> flash 0x%x (delta 0x%x)\n",$p0,$p0;

my ($x,$p)=($p0>=0?0:0,$p0);
my $cur_delta=$p-$x;
print "segment: bin 0x000000.. delta=0x",sprintf("%x",$cur_delta),"\n";
while ($x+$STEP <= $lb) {
    my $chunk=substr($B,$x,$STEP);
    $p=$x+$cur_delta;
    if ($p+$STEP<=$lf && substr($F,$p,$STEP) eq $chunk) { $x+=$STEP; next; }
    # delta changed (or gap): search a window for the chunk
    my $ws = $p-$WIN; $ws=0 if $ws<0;
    my $we = $p+$WIN; $we=$lf if $we>$lf;
    my $win = substr($F,$ws,$we-$ws);
    my $idx = index($win,$chunk);
    if ($idx>=0) {
        my $np=$ws+$idx;
        printf "segment: bin 0x%06x.. delta=0x%x (was 0x%x, shift %d, flash gap/insert 0x%x bytes)\n",
            $x,$np-$x,$cur_delta,$np-$p,($np-($x+$cur_delta));
        $cur_delta=$np-$x; $p=$np; $x+=$STEP;
    } else {
        printf "bin 0x%06x: chunk NOT FOUND (data differs / inserted / transformed)\n",$x;
        last;
    }
}
printf "done at bin 0x%x\n",$x;
