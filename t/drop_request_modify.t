#!/usr/bin/perl

# (C) han.xiao

###############################################################################

use warnings;
use strict;

use Test::More;
use File::Copy;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################


select STDERR; $| = 1;
select STDOUT; $| = 1;



my $t = Test::Nginx->new()->plan(1)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

master_process off;
daemon         off;

events {
}

http {
		%%TEST_GLOBALS_HTTP%%
    access_log    off;

    server {
        listen       8080;
        server_name  localhost;
				server_id test_id;
				drop_request 50%;
        location /echo {
            stat;
        }
        location /drop_show {
        		drop_request 100%;
            drop_request_show;
        }
    }
    
    
}

EOF

###############################################################################

$t->run();


my $ret = str_pro(http_get('/drop_show?action=modify&index=0&per=90%','8080'));

like($ret, qr/1/, 'no args');



sub str_pro
{
	#open ERR, ">/tmp/b.log";
	my ($c) = @_;
	
	my $start = index($c, "0\t90%");
	
	if(-1 != $start)
	{
		close ERR;
		return "1";
	}
	else
	{
		close ERR;
		return "0";
	}
}

