
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_config.h>
#include <ngx_murmurhash.h>
#include <ngx_http_upstream.h>
#include "ngx_http_upstream_check_module.h"
#include "ngx_http_upstream_check_handler.h"


static char * ngx_http_upstream_check_client_read_file(ngx_conf_t *cf, u_char *file, ngx_list_t *list);
static char *ngx_http_upstream_global_check(ngx_conf_t *cf, 
        ngx_command_t *cmd, void *conf);
static char *ngx_http_upstream_check(ngx_conf_t *cf,
        ngx_command_t *cmd, void *conf);
static char * ngx_http_upstream_check_http_send(ngx_conf_t *cf,
        ngx_command_t *cmd, void *conf);
static char * ngx_http_upstream_check_http_expect_alive(ngx_conf_t *cf,
        ngx_command_t *cmd, void *conf);
static char *ngx_http_upstream_check_http_expect_not_alive(ngx_conf_t *cf, ngx_command_t *cmd,
                                          void *conf);
static char * ngx_http_upstream_check_shm_size(ngx_conf_t *cf,
        ngx_command_t *cmd, void *conf);
static char * ngx_http_upstream_check_status(ngx_conf_t *cf,
        ngx_command_t *cmd, void *conf);
static char * ngx_http_upstream_check_enable(ngx_conf_t *cf,
        ngx_command_t *cmd, void *conf);
static char * ngx_http_upstream_check_disable(ngx_conf_t *cf,
        ngx_command_t *cmd, void *conf);              

static void *ngx_http_upstream_check_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_check_init_main_conf(ngx_conf_t *cf, void *conf);

static void * ngx_http_upstream_check_create_srv_conf(ngx_conf_t *cf);
static char * ngx_http_upstream_check_init_srv_conf(ngx_conf_t *cf, void *conf);

static void *ngx_http_upstream_check_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_check_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_check_init_process(ngx_cycle_t *cycle);


static ngx_conf_bitmask_t  ngx_check_http_expect_alive_masks[] = {
    { ngx_string("http_2xx"), NGX_CHECK_HTTP_2XX },
    { ngx_string("http_3xx"), NGX_CHECK_HTTP_3XX },
    { ngx_string("http_4xx"), NGX_CHECK_HTTP_4XX },
    { ngx_string("http_5xx"), NGX_CHECK_HTTP_5XX },
    { ngx_null_string, 0 }
};


//add by shengyan 2012/11/14 
static ngx_conf_bitmask_t  ngx_check_http_expect_not_alive_masks[] = {
    { ngx_string("http_400"), NGX_CHECK_HTTP_NOT_ALIVE_400},
    { ngx_string("http_403"), NGX_CHECK_HTTP_NOT_ALIVE_403},
    { ngx_string("http_404"), NGX_CHECK_HTTP_NOT_ALIVE_404},
    { ngx_string("http_408"), NGX_CHECK_HTTP_NOT_ALIVE_408},
    { ngx_string("http_499"), NGX_CHECK_HTTP_NOT_ALIVE_499},   
    { ngx_string("http_500"), NGX_CHECK_HTTP_NOT_ALIVE_500},
    { ngx_string("http_502"), NGX_CHECK_HTTP_NOT_ALIVE_502},
    { ngx_string("http_503"), NGX_CHECK_HTTP_NOT_ALIVE_503},
    { ngx_string("http_504"), NGX_CHECK_HTTP_NOT_ALIVE_504},
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_upstream_check_commands[] = {

    { ngx_string("check"),
      NGX_HTTP_UPS_CONF|NGX_CONF_1MORE,
      ngx_http_upstream_check,
      0,
      0,
      NULL },

    { ngx_string("check_http_send"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_http_upstream_check_http_send,
      0,
      0,
      NULL },

    { ngx_string("check_http_expect_alive"),
      NGX_HTTP_UPS_CONF|NGX_CONF_1MORE,
      ngx_http_upstream_check_http_expect_alive,
      0,
      0,
      NULL },
     
     //add by shengyan 2012/11/14 
    { ngx_string("check_http_expect_not_alive"),
      NGX_HTTP_UPS_CONF|NGX_CONF_1MORE,
      ngx_http_upstream_check_http_expect_not_alive,
      0,
      0,
      NULL },
      
    { ngx_string("global_check"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12,
      ngx_http_upstream_global_check,
      0,
      0,
      NULL },
      
     { ngx_string("check_enable"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_upstream_check_enable,
      0,
      0,
      NULL },
      
      { ngx_string("check_disable"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_upstream_check_disable,
      0,
      0,
      NULL }, 
    //add by shengyan 2012/12/10 
    
    { ngx_string("check_shm_size"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_upstream_check_shm_size,
      0,
      0,
      NULL },

    { ngx_string("check_status"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_upstream_check_status,
      0,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_check_module_ctx = {
    NULL,                                      /* preconfiguration */
    NULL,                                      /* postconfiguration */

    ngx_http_upstream_check_create_main_conf,  /* create main configuration */
    ngx_http_upstream_check_init_main_conf,    /* init main configuration */

    ngx_http_upstream_check_create_srv_conf,   /* create server configuration */
    NULL,                                      /* merge server configuration */

    ngx_http_upstream_check_create_loc_conf,   /* create location configuration */
    ngx_http_upstream_check_merge_loc_conf     /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_check_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_check_module_ctx,   /* module context */
    ngx_http_upstream_check_commands,      /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_check_init_process,           /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


check_conf_t *
ngx_http_get_check_type_conf(ngx_str_t *str)
{
    ngx_uint_t i;

    for (i = 0; ;i++) {

        if (ngx_check_types[i].type == 0) {
            break;
        }

        if (ngx_strncmp(str->data,
                    (u_char *)ngx_check_types[i].name, str->len) == 0) {
            return &ngx_check_types[i];
        }
    }

    return NULL;
}


ngx_uint_t
ngx_http_check_add_peer(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us,
                        ngx_peer_addr_t *peer_addr)
{
    ngx_http_check_peer_t                *peer;
    ngx_http_check_peers_t               *peers;
    ngx_http_upstream_check_srv_conf_t   *ucscf;
    ngx_http_upstream_check_main_conf_t  *ucmcf;

    if (us->srv_conf == NULL) {
        return NGX_ERROR;
    }
    
    ucmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_check_module);                                                   
    ucscf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_check_module);

    if(ucscf->check_interval == 0 && ucmcf->global_check_client_mode == 0) {  //update by shengyan 2012/12/10
        return NGX_ERROR;
    }
   
    peers = ucmcf->peers;
    peer = ngx_array_push(&peers->peers);
    if (peer == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(peer, sizeof(ngx_http_check_peer_t));

    peer->index = peers->peers.nelts - 1;
    peer->conf = ucscf;
    peer->upstream_name = &us->host;
    peer->peer_addr = peer_addr;

    peers->checksum +=
        ngx_murmur_hash2(peer_addr->name.data, peer_addr->name.len);

    return peer->index;
}


static char *
ngx_http_upstream_check_client_read_file(ngx_conf_t *cf, u_char *file, ngx_list_t *list)
{	  
	  FILE                   *fp;
	  ngx_url_t              u;
	  u_char                 *p, buf[256], upstream_name[256], host[256];
	  ngx_http_check_addr_t  *peer_addr;
	        	  
	  fp = fopen(file, "r");
    if (fp == NULL){
   	    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "check client read file %s not exist", file);
        return NGX_CONF_ERROR;
    }
    
    while(1){
    	  p = fgets(buf, 256, fp);
    	  if (p == NULL){
    		    break;	
    	  }
    	  
    	  ngx_memzero(&upstream_name, 256);
    	  ngx_memzero(&host, 256); 
    	  ngx_memzero(&u, sizeof(ngx_url_t)); 
    	  
    	  sscanf(buf, "%s %s", upstream_name, host);    	  
    	  u.url.data = host;
    	  u.url.len = ngx_strlen(host); 
        u.default_port = 80;
    	  if (ngx_parse_url(cf->pool, &u) != NGX_OK) {   
            if (u.err) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in upstream \"%V\"", u.err, &u.url);
            }
            fclose(fp);
            return NGX_CONF_ERROR;
        }
        
        peer_addr = ngx_list_push(list);
        if (peer_addr == NULL){
        	  return NGX_CONF_ERROR;
        }
        peer_addr->sockaddr = u.addrs->sockaddr;
        peer_addr->socklen = u.addrs->socklen;
        peer_addr->name = u.addrs->name; 
        
        peer_addr->upstream_name.len = ngx_strlen(upstream_name);                                 //add by shengyan 2013/02/19
        peer_addr->upstream_name.data = ngx_pcalloc(cf->pool, peer_addr->upstream_name.len);
        if (peer_addr->upstream_name.data == NULL){
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "[ngx_http_upstream_check_client_read_file]: pcalloc failed!");
            fclose(fp);
            return NGX_CONF_ERROR;                   	
        }
        ngx_memcpy(peer_addr->upstream_name.data, upstream_name, peer_addr->upstream_name.len);   //add by shengyan 2013/02/19      
    }
    fclose(fp);
    return NGX_CONF_OK;
}


static char *
ngx_http_upstream_global_check(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	  ngx_int_t                             i;
    ngx_str_t                            *value, s;
    ngx_http_upstream_check_main_conf_t  *ucmcf;
    
    value = cf->args->elts;
    ucmcf = ngx_http_conf_get_module_main_conf(cf,
            ngx_http_upstream_check_module);
            
    ucmcf->global_check_client_mode = 0;
    ucmcf->global_check_client_file.len = 0;
    ucmcf->global_check_client_file.data = NULL;
    ucmcf->global_check_client_list = NULL;
    
    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "mode=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;
            
            if (ngx_strcmp(s.data, "client") == 0){
            	  ucmcf->global_check_client_mode = 1;
            }else if (ngx_strcmp(s.data, "lb") == 0){
            	  ucmcf->global_check_client_mode = 0;
            }else{
            	  goto invalid_check_parameter;
            }
            continue;
        }

        if (ngx_strncmp(value[i].data, "file=", 5) == 0) {
        	  s.len = value[i].len - 5;
        	  s.data = value[i].data + 5;
        	  
            ucmcf->global_check_client_file.len = s.len;
            ucmcf->global_check_client_file.data = ngx_pcalloc(cf->pool, s.len + 1);            
            if (ucmcf->global_check_client_file.data == NULL){ 
            	  return NGX_CONF_ERROR;
            }
            ngx_memcpy(ucmcf->global_check_client_file.data, s.data, s.len); 
            
            continue;
        }
    }
    
    if (ucmcf->global_check_client_mode == 1){
    	  if (ucmcf->global_check_client_file.len == 0){
    	  	  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "check client mode need file");
            return NGX_CONF_ERROR;
    	  }else{
    	  	  ucmcf->global_check_client_list = ngx_list_create(cf->pool, 4, sizeof(ngx_http_check_addr_t));
    	  	  if (ucmcf->global_check_client_list == NULL){
                return NGX_CONF_ERROR; 	
    	  	  }
    	  	  return ngx_http_upstream_check_client_read_file(cf, ucmcf->global_check_client_file.data, ucmcf->global_check_client_list);
    	  }
    	  
    }

    return NGX_CONF_OK;

invalid_check_parameter:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}


static char *
ngx_http_upstream_check(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                           *value, s;
    ngx_uint_t                           i, rise, fall, default_down;
    ngx_msec_t                           interval, timeout;
    ngx_http_upstream_check_srv_conf_t  *ucscf;

    /* set default */
    rise = 2;
    fall = 5;
    interval = 30000;
    timeout = 1000;
    default_down = 1;

    value = cf->args->elts;

    ucscf = ngx_http_conf_get_module_srv_conf(cf,
                                              ngx_http_upstream_check_module);
    if (ucscf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "type=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            ucscf->check_type_conf = ngx_http_get_check_type_conf(&s);

            if (ucscf->check_type_conf == NULL) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "interval=", 9) == 0) {
            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            interval = ngx_atoi(s.data, s.len);
            if (interval == (ngx_msec_t) NGX_ERROR) {
                goto invalid_check_parameter;
            } else if (interval == 0) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {
            s.len = value[i].len - 8;
            s.data = value[i].data + 8;

            timeout = ngx_atoi(s.data, s.len);
            if (timeout == (ngx_msec_t) NGX_ERROR) {
                goto invalid_check_parameter;
            } else if (timeout == 0) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "rise=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            rise = ngx_atoi(s.data, s.len);
            if (rise == (ngx_uint_t) NGX_ERROR) {
                goto invalid_check_parameter;
            } else if (rise == 0) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "fall=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            fall = ngx_atoi(s.data, s.len);
            if (fall == (ngx_uint_t) NGX_ERROR) {
                goto invalid_check_parameter;
            } else if (fall == 0) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "default_down=", 13) == 0) {
            s.len = value[i].len - 13;
            s.data = value[i].data + 13;

            if (ngx_strcasecmp(s.data, (u_char *) "true") == 0) {
                default_down = 1;
            } else if (ngx_strcasecmp(s.data, (u_char *) "false") == 0) {
                default_down = 0;
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid value \"%s\", "
                                   "it must be \"true\" or \"false\"",
                                   value[i].data);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        goto invalid_check_parameter;
    }

    ucscf->check_interval = interval;
    ucscf->check_timeout = timeout;
    ucscf->fall_count = fall;
    ucscf->rise_count = rise;
    ucscf->default_down = default_down;

    if (ucscf->check_type_conf == NGX_CONF_UNSET_PTR) {
        s.len = sizeof("tcp") - 1;
        s.data =(u_char *) "tcp";

        ucscf->check_type_conf = ngx_http_get_check_type_conf(&s);
    }

    return NGX_CONF_OK;

invalid_check_parameter:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}


static char *
ngx_http_upstream_check_http_send(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                           *value;
    ngx_http_upstream_check_srv_conf_t  *ucscf;

    value = cf->args->elts;

    ucscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_check_module);

    ucscf->send = value[1];

    return NGX_CONF_OK;
}


static char *
ngx_http_upstream_check_http_expect_alive(ngx_conf_t *cf, ngx_command_t *cmd,
                                          void *conf)
{
    ngx_str_t                           *value;
    ngx_uint_t                           bit, i, m;
    ngx_conf_bitmask_t                  *mask;
    ngx_http_upstream_check_srv_conf_t  *ucscf;

    value = cf->args->elts;
    mask = ngx_check_http_expect_alive_masks;

    ucscf = ngx_http_conf_get_module_srv_conf(cf,
                                              ngx_http_upstream_check_module);
    bit = ucscf->code.status_alive;

    for (i = 1; i < cf->args->nelts; i++) {
        for (m = 0; mask[m].name.len != 0; m++) {

            if (mask[m].name.len != value[i].len
                || ngx_strcasecmp(mask[m].name.data, value[i].data) != 0)
            {
                continue;
            }

            if (bit & mask[m].mask) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "duplicate value \"%s\"", value[i].data);

            } else {
                bit |= mask[m].mask;
            }

            break;
        }

        if (mask[m].name.len == 0) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "invalid value \"%s\"", value[i].data);

            return NGX_CONF_ERROR;
        }
    }

    ucscf->code.status_alive = bit;
    ucscf->status_alive_flag = 1;

    return NGX_CONF_OK;
}


//add by shengyan 2012/11/14
static char *
ngx_http_upstream_check_http_expect_not_alive(ngx_conf_t *cf, ngx_command_t *cmd,
                                          void *conf)
{
    ngx_str_t                           *value;
    ngx_uint_t                           bit, i, m;
    ngx_conf_bitmask_t                  *mask;
    ngx_http_upstream_check_srv_conf_t  *ucscf;

    value = cf->args->elts;
    mask = ngx_check_http_expect_not_alive_masks;

    ucscf = ngx_http_conf_get_module_srv_conf(cf,
                                              ngx_http_upstream_check_module);
    bit = ucscf->code.status_not_alive;

    for (i = 1; i < cf->args->nelts; i++) {
        for (m = 0; mask[m].name.len != 0; m++) {

            if (mask[m].name.len != value[i].len
                || ngx_strcasecmp(mask[m].name.data, value[i].data) != 0)
            {
                continue;
            }

            if (bit & mask[m].mask) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "duplicate value \"%s\"", value[i].data);

            } else {
                bit |= mask[m].mask;
            }

            break;
        }

        if (mask[m].name.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid value \"%s\"", value[i].data);

            return NGX_CONF_ERROR;
        }
    }

    ucscf->code.status_not_alive = bit;
    ucscf->status_alive_flag = 0;

    return NGX_CONF_OK;
}


static char *
ngx_http_upstream_check_shm_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                            *value;
    ngx_http_upstream_check_main_conf_t  *ucmcf;

    ucmcf = ngx_http_conf_get_module_main_conf(cf,
            ngx_http_upstream_check_module);

    if (ucmcf->check_shm_size) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ucmcf->check_shm_size = ngx_parse_size(&value[1]);
    if (ucmcf->check_shm_size == (size_t) NGX_ERROR) {
        return "invalid value";
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_upstream_check_status(ngx_conf_t *cf,
        ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t                *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_upstream_check_status_handler;

    return NGX_CONF_OK;
}


static char *
ngx_http_upstream_check_enable(ngx_conf_t *cf,
        ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t                *clcf;
    ngx_http_upstream_check_loc_conf_t      *cclcf;
    ngx_str_t                               *value;
    ngx_str_t                               upstream_name;
    ngx_str_t                               host;
    
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_upstream_check_enable_handler;
    
    cclcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_upstream_check_module);
       
    value = cf->args->elts;
    if (cf->args->nelts == 2) {
        host = value[1];
        cclcf->upstream_index = -1;
    }else{
    	  upstream_name = value[1];
    	  host = value[2];
    	  //inverse upstream_name
        if (upstream_name.data[0] == '$') {
            upstream_name.len--;
            upstream_name.data++;

            cclcf->upstream_index = ngx_http_get_variable_index(cf, &upstream_name);
            if (cclcf->upstream_index == NGX_ERROR) {
                return NGX_CONF_ERROR;
            }        
        }else{
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &upstream_name);
            return NGX_CONF_ERROR;    
        }
    }
    
    //inverse host
    if (host.data[0] == '$') {
        host.len--;
        host.data++;

        cclcf->host_index = ngx_http_get_variable_index(cf, &host);
        if (cclcf->host_index == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }        
    }else{
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &host);
        return NGX_CONF_ERROR;    
    }
        
    return NGX_CONF_OK;
}


static char *
ngx_http_upstream_check_disable(ngx_conf_t *cf,
        ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t                *clcf;
    ngx_http_upstream_check_loc_conf_t      *cclcf;
    ngx_str_t                               *value;
    ngx_str_t                               upstream_name;
    ngx_str_t                               host;
    
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_upstream_check_disable_handler;
    
    cclcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_upstream_check_module);
       
    value = cf->args->elts;
    if (cf->args->nelts == 2) {
        host = value[1];
        cclcf->upstream_index = -1;
    }else{
    	  upstream_name = value[1];
    	  host = value[2];
    	  //inverse upstream_name
        if (upstream_name.data[0] == '$') {
            upstream_name.len--;
            upstream_name.data++;

            cclcf->upstream_index = ngx_http_get_variable_index(cf, &upstream_name);
            if (cclcf->upstream_index == NGX_ERROR) {
                 return NGX_CONF_ERROR;
            }        
        }else{
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &upstream_name);
            return NGX_CONF_ERROR;    
        }
    }
    
    //inverse host
    if (host.data[0] == '$') {
        host.len--;
        host.data++;

        cclcf->host_index = ngx_http_get_variable_index(cf, &host);
        if (cclcf->host_index == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }        
    }else{
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &host);
        return NGX_CONF_ERROR;    
    }
        
    return NGX_CONF_OK;
}


static void *
ngx_http_upstream_check_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_check_main_conf_t  *ucmcf;

    ucmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_check_main_conf_t));
    if (ucmcf == NULL) {
        return NULL;
    }

    ucmcf->peers = ngx_pcalloc(cf->pool, sizeof(ngx_http_check_peers_t));
    if (ucmcf->peers == NULL) {
        return NULL;
    }

    ucmcf->peers->checksum = 0;
    ucmcf->global_check_client_mode = 0;                 //add by shengyan 2012/12/10
    ucmcf->global_check_client_list = NULL;              //add by shengyan 2012/12/10
    ucmcf->global_check_client_file.len = 0;             //add by shengyan 2012/12/10
    ucmcf->global_check_client_file.data = NULL;         //add by shengyan 2012/12/10
    
    if (ngx_array_init(&ucmcf->peers->peers, cf->pool, 16,
                sizeof(ngx_http_check_peer_t)) != NGX_OK)
    {
        return NULL;
    }

    return ucmcf;
}


static void *
ngx_http_upstream_check_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_check_srv_conf_t  *ucscf;

    ucscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_check_srv_conf_t));
    if (ucscf == NULL) {
        return NULL;
    }

    ucscf->fall_count = NGX_CONF_UNSET_UINT;
    ucscf->rise_count = NGX_CONF_UNSET_UINT;
    ucscf->check_timeout = NGX_CONF_UNSET_MSEC;
    ucscf->check_type_conf = NGX_CONF_UNSET_PTR;
    ucscf->status_alive_flag = NGX_CONF_UNSET_UINT;  //add by shengyan 2012/12/10

    return ucscf;
}


static void *
ngx_http_upstream_check_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_check_loc_conf_t  *conf;
 
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_check_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->host_index = -1;
    conf->upstream_index = -1;
    
    return conf;
}
 

static char *
ngx_http_upstream_check_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_uint_t                            i;
    ngx_http_upstream_srv_conf_t        **uscfp;
    ngx_http_upstream_main_conf_t        *umcf;

    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;
    
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (ngx_http_upstream_check_init_srv_conf(cf, uscfp[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }
    return ngx_http_upstream_check_init_shm(cf, conf);
   
}


static char *
ngx_http_upstream_check_init_srv_conf(ngx_conf_t *cf, void *conf)
{
    check_conf_t                        *check;
    ngx_http_upstream_srv_conf_t        *us = conf;
    ngx_http_upstream_check_srv_conf_t  *ucscf;

    if (us->srv_conf == NULL) {
        return NGX_CONF_OK;
    }

    ucscf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_check_module);

    if (ucscf->fall_count == NGX_CONF_UNSET_UINT) {
        ucscf->fall_count = 2;
    }

    if (ucscf->rise_count == NGX_CONF_UNSET_UINT) {
        ucscf->rise_count = 5;
    }

    if (ucscf->check_interval == NGX_CONF_UNSET_MSEC) {
        ucscf->check_interval = 0;
    }

    if (ucscf->check_timeout == NGX_CONF_UNSET_MSEC) {
        ucscf->check_timeout = 1000;
    }

    if (ucscf->check_type_conf == NGX_CONF_UNSET_PTR) {
        ucscf->check_type_conf = NULL;
    }
    
    if (ucscf->status_alive_flag == NGX_CONF_UNSET_UINT){  //add by shengyan 2012/12/10
       ucscf->status_alive_flag = 1;	
    }

    check = ucscf->check_type_conf;
    if (check) {
        if (ucscf->send.len == 0) {
            ucscf->send.data = check->default_send.data;
            ucscf->send.len = check->default_send.len;
        }

        if (ucscf->code.status_alive == 0 && ucscf->status_alive_flag == 1) {      //add by shengyan 2012/12/10
            ucscf->code.status_alive = check->default_status_alive;
        }
        
        if (ucscf->code.status_not_alive == 0 && ucscf->status_alive_flag == 0) {  //add by shengyan 2012/12/10
            ucscf->code.status_not_alive = NGX_CHECK_HTTP_NOT_ALIVE_404;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_upstream_check_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_upstream_check_loc_conf_t *prev = parent;
    ngx_http_upstream_check_loc_conf_t *conf = child;
 
    ngx_conf_merge_value(conf->host_index, prev->host_index, -1); 
    ngx_conf_merge_value(conf->upstream_index, prev->upstream_index, -1);
    
    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_check_init_process(ngx_cycle_t *cycle)
{
    return ngx_http_check_add_timers(cycle);
}
