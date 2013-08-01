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
		drop_request 50%;

    server {
        listen       8080;
        server_name  localhost;
				server_id test_id;
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

for(my $i = 1; $i <= 100; $i++)
{
	http_get('/echo','8080')
}
my $ret = str_pro(http_get('/drop_show','8080'));

like($ret, qr/1/, 'no args');
#like(http_get('/echo','8080'), qr/test_id.*1.*50.00%.*1.*0/, 'no args');
#like(http_get('/echo?show=sslcache','8888'), qr/\b((?!server_id)\w)+\b/, 'show=sslcache');
#like(http_get('/echo?show=servers','8888'), qr/\b((?!cache_name)\w)+\b/, 'show=servers');
#like(http_get('/echo?show=tmp_servers','8888'), qr/tmp_requests[\s\S]*test2_id.*4.*80.00%.*4.*0/, 'show=tmp_servers');



sub str_pro
{
	#open ERR, ">/tmp/b.log";
	my ($c) = @_;
	
	my $start = index($c, "0\t50%");

	my $new_string = substr($c, $start);

	my @split_string = split(/\t/, $new_string);
	#print ERR $split_string[3]-$split_string[4];
	
	if(($split_string[3]-$split_string[4]) <= 10 && ($split_string[3]-$split_string[4]) >= -10)
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

