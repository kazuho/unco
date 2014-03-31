#! /usr/bin/perl

use strict;
use warnings;

use POSIX qw(getcwd);
use Test::More tests => 3;

my $TEST_DIR = "/tmp/unco-test";
my $TEST_CWD = "$TEST_DIR/root";

my $script_dir = $ARGV[0]
	or die "Usage: $0 <script-dir>\n";
if ($script_dir !~ m{^/}) {
	$script_dir = getcwd() . "/$script_dir";
}

# setup env
system("rm -rf $TEST_DIR") == 0
	or die "failed to clean test dir:$?\n";
$ENV{"UNCO_HOME"} = "$TEST_DIR/.unco";
system("mkdir -p $TEST_CWD && touch $TEST_CWD/_placeholder_") == 0
	or die "failed to create root dir for tests:$!";
chdir($TEST_CWD)
	or die "failed to chdir to root dir for test:$!";

# run the init script and take sig
system("$script_dir/setup.sh") == 0
	or die "$script_dir/setup.sh failed:$?\n";
my $sig_post_init = create_sig();

# run the changing script and take sig
system("unco", "record", "sh", "$script_dir/test.sh") == 0
	or die "$script_dir/test.sh failed:$?\n";
my $sig_post_record = create_sig();

# undo and take sig, test
system("unco", "undo", "1") == 0
	or die "failed to undo the recorded changes:$?\n";
is create_sig(), $sig_post_init, "undo-vs-post_init";

# redo and take sig, test
system("unco", "redo", "1") == 0
	or die "failed to redo the recorded changes:$?\n";
is create_sig(), $sig_post_record, "redo-vs-post_record";

# undo once more and take sig, test
system("unco", "undo", "1") == 0
	or die "failed to re-undo the recorded changes:$?\n";
is create_sig(), $sig_post_init, "re_undo-vs-post-init";


sub create_sig {
	open my $fh, "-|", "gnutar cf - *"
		or die "popen failed:$!";
	my $sig = join "", <$fh>;
	close $fh;
	die "gnutar failed:$?"
		if $? != 0;
	$sig;
}
