#!/bin/sh
./configure --prefix=output --add-module=addon/ngx_http_reqstat_module/ --with-http_stub_status_module 
make
make install
