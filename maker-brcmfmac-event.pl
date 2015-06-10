#!/usr/bin/perl

use strict;

	my $pahole = $ARGV[0];
	my $sName = $ARGV[1];
	my $cmdName = $ARGV[2];
	my $fieldPrefix = $ARGV[3];	# optional

	if (not defined $pahole or
	    not defined $sName or
	    not defined $cmdName) {
		die "Usage:\n\tmaker-brcmfmac-event.pl <pahole> <struct> <cmd> [prefix]\n";
	}

	my $sData = "";
	my $found = 0;

	my $c = "";
	my $d = "";

	# Grab command nr
	my $cmdTmp = `cat fweh.h | grep $cmdName`;
	$cmdTmp =~ /(\d+)/;
	my $cmdNr = $1;

	my $line;
	open(FD, $pahole);
	while( $line = <FD>) {
		# struct typeName {
		#...
		# };
		#typedef struct {
		#...
		# } typeName;
		if ($line =~ /struct $sName {/) {
			$found = 1;
			$sData = ""
		}
		elsif ($found && $line =~ /};/) {
			last;
		}
		else {
			$sData .= $line;
		}
	}

	if (!$found) {
		die ("struct not found");
	}

	$c .= "\t\telseif (cmd == $cmdNr) then\n";
	$c .= "\t\t\t-- $cmdName\n";

	my @lines = split /\n/, $sData;
	foreach $line (@lines) {
		# Match the following string:
		# /* XXX 1 byte hole, try to pack */
		if ($line =~ /.*\/\* XXX (\S+) byte.* hole, try to pack \*\//) {
			$c .= "\t\t\tn = n + $1 -- padding in struct\n";
			next;
		}

		# Match strings like these:
		#        } rateset;                                       /*    52    20 */
		if ($line =~ /.*}.*/) {
			next;
		}

		# Match strings like these:
		# __le32                     version;              /*     0     4 */
		if ($line !~ /\s+(\S+)\s+(\S+);\s+\S+\s+(\S)+\s+(\S+)/) {
			next;
		}
		my $type = $1;
		my $name = $2;
		my $offset = $3;
		my $size = $4;
		print "$size-$name\n";

		if ($fieldPrefix ne "") {
			$name = $fieldPrefix . "_" . $name;
		}

		#Remove array
		$name =~ s/\[\d+\]//;

		my $fn = $cmdName."_$name";

		$c .= "\t\t\tpar:add_le(f.$fn, buffer(n, $size)); n = n + $size\n";

		if ($size == 6 && $name eq "bssid") {
			$d .= "f.$fn = ProtoField.ether(\"bcm_event.$fn\", \"$name\")\n";
		} elsif ($size == 6 && $name eq "ea") {
			$d .= "f.$fn = ProtoField.ether(\"bcm_event.$fn\", \"$name\")\n";
		} elsif ($size == 1) {
			$d .= "f.$fn = ProtoField.uint8(\"bcm_event.$fn\", \"$name\")\n";
		} elsif ($size == 2) {
			$d .= "f.$fn = ProtoField.uint16(\"bcm_event.$fn\", \"$name\")\n";
		} elsif ($size == 4) {
			$d .= "f.$fn = ProtoField.uint32(\"bcm_event.$fn\", \"$name\")\n";
		} else {
			$d .= "f.$fn = ProtoField.bytes(\"bcm_event.$fn\", \"$name\")\n";
		}
	}

	print $c;
	print "\n";
	print $d;

