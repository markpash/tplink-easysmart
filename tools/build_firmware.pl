#!/usr/bin/env perl
# Build size-changing TP-Link TL-SG108E V6.0 images that the default loader accepts.
#
# Model (see docs/FIRMWARE_FORMAT.md):
#   file = 20-byte header + payload ; the header is duplicated at file 0x4012.
#   f8  = (sum(header[0:8]) + sum(header[12:20])) & 0xFFFF        (loader check)
#   f12 = sum(payload) + C                                        (boot check)
#   payload = file[0x14:], logic image = segment A (0x2E0C) ++ segment B.
#   The loader writes segment A at flash 0x1002 and segment B at 0x1BE0E,
#   preserving the fixed 0x18000 runtime at 0x3E0E. Only segment B can grow.
#
# Two construction modes for growing (segment B only):
#   --model a : f12_new = f12_old + sum(appended).  Assumes the checksum window
#               scales with the payload (the natural reading of the boot code).
#               Works for arbitrary appended content.
#   --model b : f12 unchanged.  Only valid when the appended block sums to 0
#               (e.g. `--zero N`), because a plain byte-sum cannot cancel an
#               arbitrary 32-bit value with a short trailer.
#
# Usage:
#   build_firmware.pl info   <firmware.bin>
#   build_firmware.pl verify <firmware.bin>
#   build_firmware.pl append <in.bin> <out.bin> --data BLOB [--model a]
#   build_firmware.pl append <in.bin> <out.bin> --append-hex 0011aabb --model a
#   build_firmware.pl append <in.bin> <out.bin> --zero 4096          # model b
use strict;
use warnings;

my $FIXED_C = 0x13EC;         # boot sum = sum(payload excluding app header) + C
my $APP_HDR_OFF = 0x3FFE;     # offset of the 20-byte app header within the payload
my $SEG_A   = 0x2E0C;         # payload bytes in segment A (fixed)
my $SEG_B_FLASH = 0x1BE0E;    # flash start of segment B
my $CONFIG_FLASH = 0x1FC000;  # start of config region (segment B must stay below)
my $XORF12  = 1;              # documentation flag (not used)

sub u32 { return $_[0] & 0xffffffff; }
sub rd32be { return unpack("N", substr($_[0], $_[1], 4)); }
sub wr32be { return pack("N", u32($_[0])); }
sub sumb { my $s=0; $s+=$_ for unpack("C*", $_[0]); return u32($s); }

sub loadf { my ($f)=@_; open(my $h,"<:raw",$f) or die "cannot open $f: $!\n"; local $/; my $d=<$h>; close $h; return $d; }
sub savef { my ($f,$d)=@_; open(my $h,">:raw",$f) or die "cannot write $f: $!\n"; print $h $d; close $h; }

sub header_of {
    my ($bin) = @_;
    return {
        magic   => substr($bin,0,2),
        type    => substr($bin,2,2),
        length  => rd32be($bin,4),
        f8      => rd32be($bin,8) & 0xffff,
        f12     => rd32be($bin,12),
        tail    => substr($bin,16,4),
    };
}

sub f8_for {
    my ($hdr20) = @_;
    my $s = 0;
    $s += $_ for unpack("C*", substr($hdr20,0,8));
    $s += $_ for unpack("C*", substr($hdr20,12,8));
    return $s & 0xffff;
}

sub make_header {
    my ($tmpl, $length, $f8, $f12) = @_;
    my $h = substr($tmpl,0,20);
    substr($h,4,4)  = wr32be($length);
    substr($h,8,4)  = wr32be($f8);
    substr($h,12,4) = wr32be($f12);
    return $h;
}

sub check_size {
    my ($payload_len, $added) = @_;
    my $segB_flash = $SEG_B_FLASH + ($payload_len - $SEG_A);
    my $end = $segB_flash;
    my $free = $CONFIG_FLASH - $end;
    printf "segment B: flash 0x%06X..0x%06X  (+%d bytes, free before config: %d / 0x%X)\n",
        $SEG_B_FLASH, $end, $added, $free, $free;
    if ($free < 0) { die "ERROR: segment B would overlap config at flash 0x1FC000\n"; }
}

sub cmd_info {
    my ($f) = @_;
    my $bin = loadf($f);
    my $plen = length($bin) - 0x14;
    my $p = substr($bin,0x14);
    printf "file      : %s (%d bytes)\n", $f, length($bin);
    for my $off (0x0, 0x4012) {
        my $h = header_of(substr($bin,$off));
        printf "header 0x%05x: type=%s len=0x%x f8=0x%04x f12=0x%08x tail=%s\n",
            $off, unpack("H*",$h->{type}), $h->{length}, $h->{f8}, $h->{f12}, unpack("H*",$h->{tail});
    }
    printf "payload   : %d bytes (0x%x)  segA=0x%x segB=%d\n", $plen, $plen, $SEG_A, $plen-$SEG_A;
    my $sum = u32(sumb($p) - sumb(substr($p,$APP_HDR_OFF,20)));
    printf "sum(payload excl app-header)=0x%08x  f12-sum = 0x%x (C, expect 0x%x)\n",
        $sum, u32(rd32be($bin,12)-$sum), $FIXED_C;
    check_size($plen, 0);
}

sub cmd_verify {
    my ($f) = @_;
    my $bin = loadf($f);
    for my $off (0x0, 0x4012) {
        my $h20 = substr($bin,$off,20);
        my $want = f8_for($h20);
        my $got  = rd32be($bin,$off+8) & 0xffff;
        printf "header 0x%05x f8: got 0x%04x expected 0x%04x %s\n",
            $off,$got,$want, ($got==$want?"OK":"MISMATCH");
    }
    my $p = substr($bin,0x14);
    my $sum = u32(sumb($p) - sumb(substr($p,$APP_HDR_OFF,20)));
    my $diff = u32(rd32be($bin,12) - $sum);
    printf "boot sum (payload excl app-header) = 0x%08x; f12-sum = 0x%x %s\n",
        $sum, $diff, ($diff==$FIXED_C ? "(C OK)" : "(C MISMATCH, expected 0x$FIXED_C)");
}

sub cmd_append {
    my ($in,$out,$blob,$mode) = @_;
    my $bin = loadf($in);
    my $payload = substr($bin,0x14);
    my $old_len = rd32be($bin,4);
    my $old_f12 = rd32be($bin,12);
    my $old_f8  = rd32be($bin,8) & 0xffff;
    die "length field (0x$old_len) != payload length (".length($payload).")\n"
        unless $old_len == length($payload);

    my $appended = $blob;
    my $f12 = $old_f12;
    my $asum = sumb($appended);
    if ($mode eq 'a') {
        $f12 = u32($old_f12 + $asum);
        printf "model a: appended sum 0x%x; f12 0x%08x -> 0x%08x\n", $asum, $old_f12, $f12;
    } else { # b
        die sprintf("model b requires appended block sum 0 (got 0x%x); use --zero N or --model a\n",$asum)
            if $asum != 0;
        print "model b: appended block sums to 0; f12 unchanged\n";
    }

    my $new_payload = $payload . $appended;
    my $new_len = length($new_payload);
    my $new_header = make_header(substr($bin,0,20), $new_len, 0, $f12);
    substr($new_header,8,4) = wr32be(f8_for($new_header));

    # rebuild: header + payload, with the duplicated header at file 0x4012
    my $second_off_in_payload = 0x4012 - 0x14;
    substr($new_payload, $second_off_in_payload, 20) = $new_header;
    my $newbin = $new_header . $new_payload;

    check_size($new_len, length($appended));
    savef($out, $newbin);
    printf "wrote %s: payload %d -> %d bytes, f8=0x%04x, f12=0x%08x (mode %s)\n",
        $out, length($payload), $new_len, rd32be($new_header,8)&0xffff, $f12, $mode;
}

# ---- arg parsing ----
my $cmd = shift @ARGV // '';
if ($cmd eq 'info')   { cmd_info($ARGV[0] // die "need file\n"); exit 0; }
if ($cmd eq 'verify') { cmd_verify($ARGV[0] // die "need file\n"); exit 0; }
if ($cmd eq 'append') {
    my ($in,$out) = (shift @ARGV, shift @ARGV);
    die "usage: append <in> <out> --data FILE | --append-hex HEX [--neutral|--model a]\n"
        unless defined $in && defined $out;
    my ($blob,$mode);
    while (@ARGV) {
        my $a = shift @ARGV;
        if    ($a eq '--data')        { $blob = loadf(shift @ARGV); }
        elsif ($a eq '--append-hex')  { $blob = pack("H*", (shift @ARGV) =~ s/\s//gr); }
        elsif ($a eq '--zero')        { $blob = "\0" x (shift @ARGV); $mode //= 'b'; }
        elsif ($a eq '--model')       { $mode = shift @ARGV; }
        else { die "unknown option $a\n"; }
    }
    die "need --data, --append-hex or --zero\n" unless defined $blob;
    $mode //= 'a';
    die "--model must be 'a' or 'b'\n" unless $mode eq 'a' || $mode eq 'b';
    cmd_append($in,$out,$blob,$mode);
    exit 0;
}
die "commands: info | verify | append\n";
