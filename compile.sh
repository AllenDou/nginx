TOPDIR=$PWD

cd $TOPDIR/nginx-1.4.2
patch -p1 < ../addon/spanner142-1.0.patch
patch -p1 < ../addon/reqstat-1.1.patch

export LUAJIT_LIB=/usr/local/lib/
export LUAJIT_INC=/usr/local/include/luajit-2.0/ 
#export LD_LIBRARY_PATH=$LUAJIT_LIB:$LD_LIBRARY_PATH
CFLAGS="-g -Wno-sign-compare -Wno-implicit-function-declaration -Wno-uninitialized -Wno-pointer-sign" ./configure --with-ld-opt="-Wl,-rpath,$LUAJIT_LIB" --prefix=output --with-debug --with-pcre=../libs/pcre-8.32 --with-http_ssl_module --with-http_stub_status_module --add-module=../addon/ngx_http_barrier_module/ --add-module=../addon/ngx_upstream_ci_module/ --add-module=../addon/ngx_http_server_status_module/ --add-module=../addon/ngx_http_tracker_module/ --add-module=../addon/ngx_upstream_check_module/ --add-module=../addon/lua-nginx-module/ --with-openssl=../libs/openssl-1.0.1e --add-module=../addon/ngx_http_limit_qps_module/ --add-module=../addon/ngx_http_reqstat_module/
touch ../libs/openssl-1.0.1e/Makefile
make 2>&1 |tee make.log && make install

cd $TOPDIR/nginx-1.4.2
