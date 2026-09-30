#!/usr/bin/env perl
# tplink-fw: patch a TP-Link Easy Smart firmware .bin so the default loader and
# bootloader accept it (both checks are additive, so they are recomputed).
#
# Firmware header (20 bytes, duplicated at file offset 0x4012):
#   0   12 34            magic
#   2   10 86            type
#   4   u32 BE           payload length
#   8   u32 BE           f8  (low 16 bits = 16-bit sum of header bytes [0:8]+[12:20])
#   12  u32 BE           f12 (32-bit additive checksum of the image, checked at boot)
#   16  33 22 55 ff      magic
#
# Checksum model:
#   * The bootloader verifies a 32-bit additive byte-sum of the image -> f12.
#   * Editing payload bytes changes f12 by  sum(new) - sum(old).
#   * The loader validates f8, which itself covers f12 -> recompute after f12.
#
# Usage:
#   tplink-fw info    fw.bin
#   tplink-fw verify  fw.bin
#   tplink-fw patch   in.bin out.bin '0x100D85=47' '0x100D90=41 42'
#   tplink-fw patch   in.bin out.bin --replace 'Here you can configure=HERE you can configure'
#   tplink-fw patch   in.bin out.bin --transpose 0x100D85 0x100D86
use strict; use warnings;

my @HDRS = (0, 0x4012);           # both header copies
use constant F8  => 8;
use constant F12 => 12;
use constant F16 => 16;

sub slurp { my $f=shift; open(my $h,"<:raw",$f) or die "$f: $!"; local $/; my $d=<$h>; close $h; return $d; }
sub spit  { my ($f,$d)=@_; open(my $h,">:raw",$f) or die "$f: $!"; print $h $d; close $h; }

sub check_magic {
    my $d=shift;
    for my $h (@HDRS) {
        die sprintf("header magic mismatch at 0x%x\n",$h)
            unless substr($d,$h,2) eq "\x12\x34";
    }
}

sub f8_expected {
    my ($d,$h)=@_;
    my $s=0; $s += ord(substr($d,$h+$_,1)) for (0..7, 12..19);
    return $s & 0xffff;
}

# NOTE: operates on $_[0] by alias so the caller's buffer is modified.
sub fix_headers {
    my $delta=$_[1];
    for my $h (@HDRS) {
        my $f12 = unpack("N", substr($_[0],$h+F12,4));
        my $nf  = ($f12 + $delta) & 0xffffffff;
        substr($_[0],$h+F12,4) = pack("N",$nf);
        my $f8  = f8_expected($_[0],$h);
        substr($_[0],$h+F8,4)  = pack("N",$f8);
        printf "header[0x%05x]: f12 0x%08x -> 0x%08x | f8 -> 0x%08x\n",$h,$f12,$nf,$f8;
    }
}

sub cmd_info {
    my $d=slurp($_[0]);
    check_magic($d);
    printf "file      : %s (%d bytes)\n",$_[0],length($d);
    for my $h (@HDRS) {
        printf "header 0x%05x: type=%s len=0x%x f8=0x%08x f12=0x%08x f16=0x%08x\n",
            $h, unpack("H*",substr($d,$h+2,2)), unpack("N",substr($d,$h+4,4)),
            unpack("N",substr($d,$h+F8,4)), unpack("N",substr($d,$h+F12,4)),
            unpack("N",substr($d,$h+F16,4));
    }
}

sub cmd_verify {
    my $d=slurp($_[0]); my $ok=1;
    for my $h (@HDRS) {
        my $got=unpack("N",substr($d,$h+F8,4)) & 0xffff;
        my $exp=f8_expected($d,$h);
        printf "header 0x%05x f8: got 0x%04x expected 0x%04x %s\n",$h,$got,$exp,($got==$exp?"OK":"MISMATCH");
        $ok &&= ($got==$exp);
    }
    exit($ok?0:1);
}

sub cmd_patch {
    my ($in,$out,@ops)=@_;
    my $d=slurp($in); check_magic($d);
    my @edits;   # [off, oldbyte, newbyte]
    while (@ops) {
        my $a=shift @ops;
        if ($a eq '--transpose') {
            my ($x,$y)=(hex(shift @ops),hex(shift @ops));
            push @edits,[$x,ord(substr($d,$x,1)),ord(substr($d,$y,1))],
                        [$y,ord(substr($d,$y,1)),ord(substr($d,$x,1))];
        } elsif ($a eq '--replace') {
            my $spec=shift @ops; my ($old,$new)=split(/=/,$spec,-1);
            die "--replace needs old=new\n" unless defined $new;
            die "length mismatch in --replace\n" unless length($old)==length($new);
            my $p=0; my $n=0;
            while (($p=index($d,$old,$p))>=0) {
                for my $i (0..length($old)-1) {
                    push @edits,[$p+$i,ord(substr($d,$p+$i,1)),ord(substr($new,$i,1))];
                }
                $p+=length($old); $n++;
            }
            print "replace: $n occurrence(s) of \"$old\"\n";
        } elsif ($a =~ /^(0x[0-9a-fA-F]+|\d+)\s*=\s*([0-9a-fA-F ]+)$/) {
            my ($offstr,$hex)=($1,$2); $hex=~s/\s//g;
            my $off=($offstr=~/^0x/)?hex($offstr):$offstr;
            my @nb=unpack("C*",pack("H*",$hex));
            push @edits, [$off+$_, ord(substr($d,$off+$_,1)), $nb[$_]] for 0..$#nb;
        } else { die "bad argument: $a\n"; }
    }
    my $delta=0;
    for my $e (@edits) {
        my ($o,$old,$new)=@$e;
        die sprintf("offset 0x%x out of range\n",$o) if $o>=length($d);
        next if $old==$new;
        $delta=($delta+$new-$old)&0xffffffff;
        substr($d,$o,1)=chr($new);
    }
    printf "edits=%d sum-delta=0x%08x\n",scalar(@edits),$delta;
    fix_headers($d,$delta);
    spit($out,$d);
    printf "wrote %s (%d bytes)\n",$out,length($d);
}

my $cmd = shift @ARGV // 'info';
if    ($cmd eq 'info')    { cmd_info(@ARGV); }
elsif ($cmd eq 'verify')  { cmd_verify(@ARGV); }
elsif ($cmd eq 'patch')   { cmd_patch(@ARGV); }
else { die "usage: $0 info|verify|patch ...\n"; }
