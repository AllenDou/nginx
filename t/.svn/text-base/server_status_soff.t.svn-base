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



my $t = Test::Nginx->new()->plan(5)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

master_process off;
daemon         off;

events {
}

http {
		%%TEST_GLOBALS_HTTP%%
    access_log    off;

    server_status_global on;

    server {
        listen       8080;
        server_name  localhost;
        server_status on;
				server_id test_id;
        location /echo {
            stat;
        }
    }
    
    server {
        listen       8888;
        server_name  localhost;
        server_status off;
				server_id test2_id;
        location /echo {
            stat;
        }
    }
}

EOF


$t->run();

like(http_get('/echo','8888'), qr/test2_id.*0.*0.00%.*0.*0/, 'no args');
like(http_get('/echo','8080'), qr/test_id.*1.*100.00%.*1.*0/, 'no args');
like(http_get('/echo?show=sslcache','8888'), qr/\b((?!server_id)\w)+\b/, 'show=sslcache');
like(http_get('/echo?show=servers','8888'), qr/\b((?!cache_name)\w)+\b/, 'show=servers');
like(http_get('/echo?show=tmp_servers','8888'), qr/tmp_requests[\s\S]*test2_id.*0.*0.00%.*0.*0/, 'show=tmp_servers');


