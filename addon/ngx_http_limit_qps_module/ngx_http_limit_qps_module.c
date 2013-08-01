
/*
 * Copyright (C) shengyan
 * DateTime: 2013/05/14
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef ngx_int_t (*ngx_http_limit_qps_action_pt) (ngx_http_request_t *r, ngx_http_variable_value_t *server_name_vv);

typedef struct {
    ngx_uint_t       max;            
    ngx_msec_t       last;    
    ngx_uint_t       freeze;
    ngx_uint_t       real_count;
    ngx_uint_t       limit_count;     
    ngx_uint_t       count;
       
    ngx_atomic_t     lock;
    ngx_atomic_int_t lock_value;  
    
    ngx_str_t        server_name;
    ngx_uint_t       server_index;
    
} ngx_http_limit_qps_server_shm_t;


typedef struct {
    ngx_http_limit_qps_server_shm_t  server[1];
} ngx_http_limit_qps_servers_shm_t;


typedef struct{
	  ngx_uint_t                        enable;	  	    
	  ngx_uint_t                        interval; 
	  ngx_uint_t                        max;
	  
	  ngx_uint_t                        server_number;
	  ngx_str_t                         *servers_name;		  	  	   
    ngx_hash_t                        servers_in_hash;
       
    ngx_uint_t                        hash_max_size;          
    ngx_uint_t                        hash_bucket_size;         
    ngx_uint_t                        forbidden_status_code;  

	  ngx_int_t                         server_name_index;
	  ngx_int_t                         server_weight_index;
	  ngx_str_t                         server_name_var;	  	  	  
	  ngx_str_t                         server_weight_var;
	  ngx_int_t                         server_default_weight;
	  
    ngx_str_t                         manager; 
    ngx_list_t                        *protect_servers; 	  
	  ngx_http_limit_qps_action_pt      handler;  
	  
    ngx_http_limit_qps_servers_shm_t  *servers_shm;    
}ngx_http_limit_qps_conf_t;


static void ngx_http_limit_qps_spinunlock(ngx_atomic_t *lock, ngx_atomic_int_t lock_value);
static ngx_http_limit_qps_server_shm_t *ngx_http_limit_qps_find_server_shm(ngx_http_limit_qps_conf_t *lqcf, ngx_str_t *name);
static ngx_uint_t *ngx_http_limit_qps_hash_find_server_index(ngx_http_limit_qps_conf_t *lqcf, ngx_http_variable_value_t *server_name_vv);
static ngx_int_t ngx_http_limit_qps_find_manage_server(ngx_http_limit_qps_conf_t *lqcf, ngx_http_variable_value_t *server_name_vv);
static ngx_int_t ngx_http_limit_qps_list_find_protect_server(ngx_http_limit_qps_conf_t *lqcf, ngx_http_variable_value_t *server_name_vv);
static ngx_int_t ngx_http_limit_qps_watch_mode (ngx_http_request_t *r, ngx_http_variable_value_t *server_name_vv);
static ngx_int_t ngx_http_limit_qps_random_mode (ngx_http_request_t *r, ngx_http_variable_value_t *server_name_vv);
static ngx_int_t ngx_http_limit_qps_protect_mode (ngx_http_request_t *r, ngx_http_variable_value_t *server_name_vv);
static ngx_int_t ngx_http_limit_qps_lookup(ngx_http_request_t *r, ngx_http_limit_qps_conf_t *lqcf, ngx_http_limit_qps_server_shm_t *server_shm);
static ngx_int_t ngx_http_limit_qps_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_limit_qps_status_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_limit_qps_init_zone(ngx_shm_zone_t *shm_zone, void *data);
static ngx_int_t ngx_http_limit_qps_init(ngx_conf_t *cf);
static char *ngx_http_limit_qps_set_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_limit_qps_protect_servers(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_limit_qps(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_limit_qps_create_conf(ngx_conf_t *cf);


static ngx_conf_num_bounds_t  ngx_http_limit_qps_status_bounds = {
    ngx_conf_check_num_bounds, 400, 599
};


static ngx_command_t  ngx_http_limit_qps_commands[] = {

    { ngx_string("limit_qps"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
      ngx_http_limit_qps,
      0,
      0,
      NULL },
      
    { ngx_string("limit_qps_manage_server"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_limit_qps_conf_t, manager),
      NULL },  
      
    { ngx_string("limit_qps_protect_servers"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
      ngx_http_limit_qps_protect_servers,
      0,
      0,
      NULL },

    { ngx_string("limit_qps_status"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_limit_qps_set_status,
      0,
      0,
      NULL },
      
    { ngx_string("limit_qps_servers_hash_max_size"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_limit_qps_conf_t, hash_max_size),
      NULL },

    { ngx_string("limit_qps_servers_hash_bucket_size"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_limit_qps_conf_t, hash_bucket_size),
      NULL },
      
    { ngx_string("limit_qps_fobbiden_status_code"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_limit_qps_conf_t, forbidden_status_code),
      &ngx_http_limit_qps_status_bounds }, 

      ngx_null_command
};


static ngx_http_module_t  ngx_http_limit_qps_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_limit_qps_init,               /* postconfiguration */

    ngx_http_limit_qps_create_conf,        /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_limit_qps_module = {
    NGX_MODULE_V1,
    &ngx_http_limit_qps_module_ctx,       /* module context */
    ngx_http_limit_qps_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void 
ngx_http_limit_qps_spinunlock(ngx_atomic_t *lock, ngx_atomic_int_t lock_value)
{
    ngx_atomic_cmp_set(lock, lock_value, 0);	 
}


static ngx_http_limit_qps_server_shm_t *
ngx_http_limit_qps_find_server_shm(ngx_http_limit_qps_conf_t *lqcf, ngx_str_t *name)
{
    ngx_uint_t                         i;
    ngx_http_limit_qps_servers_shm_t   *oservers_shm = lqcf->servers_shm;
    ngx_http_limit_qps_server_shm_t    *oserver_shm;

    if (name->len == 0){
        return NULL;	
    }
    
    for (i = 0; i < lqcf->server_number; i++) {

        oserver_shm = &oservers_shm->server[i];

        if (oserver_shm->server_name.len != name->len) {
            continue;
        }

        if (ngx_memcmp(oserver_shm->server_name.data, name->data, name->len) == 0) {
            return oserver_shm;
        }
    }

    return NULL;
}


static ngx_uint_t *
ngx_http_limit_qps_hash_find_server_index(ngx_http_limit_qps_conf_t *lqcf, ngx_http_variable_value_t *server_name_vv)
{
	  ngx_uint_t        key;
	  ngx_uint_t        *index;
	
	  if (server_name_vv->len == 0){
	      return NULL;		  	
	  }
	  
	  key = ngx_hash_key_lc(server_name_vv->data, server_name_vv->len);
	  
    index = (ngx_uint_t *)ngx_hash_find(&lqcf->servers_in_hash, key,
                               server_name_vv->data, server_name_vv->len);
                                 	                                                     
    return index;                               
}


static ngx_int_t 
ngx_http_limit_qps_find_manage_server(ngx_http_limit_qps_conf_t *lqcf, ngx_http_variable_value_t *server_name_vv)
{
    if (server_name_vv == NULL){
	      return NGX_ERROR;	
	  }	  
	  	  
	  if (lqcf->manager.len != server_name_vv->len){
	      return NGX_ERROR;		
	  }	 
	           
	  if (ngx_memcmp(lqcf->manager.data, server_name_vv->data, server_name_vv->len) != 0){
	      return NGX_ERROR;
	  }
	  
	  return NGX_OK;
}


static ngx_int_t
ngx_http_limit_qps_list_find_protect_server(ngx_http_limit_qps_conf_t *lqcf, ngx_http_variable_value_t *server_name_vv)
{
	  ngx_uint_t             i;
	  ngx_list_t             *list;	  
	  ngx_list_part_t        *part;
	  ngx_str_t              *server;

    if (server_name_vv == NULL){
        return NGX_ERROR;		
    }

	  list = lqcf->protect_servers;
	  if (list == NULL){
		    return NGX_ERROR;		
	  }
	  
	  part = &(list->part);
	  server = (ngx_str_t *)part->elts;
	  
	  for (i=0; ; i++){
	      if (i >= part->nelts){
	    	    if (part->next == NULL){
	    	        break;	
	    	    }
	    	    part = part->next;
	    	    server = (ngx_str_t *)part->elts;
	    	    i = 0;
	      }
	      
	      if (server[i].len != server_name_vv->len) {
            continue;
        }
                     
        if (ngx_memcmp(server[i].data, server_name_vv->data, server_name_vv->len) == 0){
            return NGX_OK;	
        }       
	  }
	  
	  return NGX_ERROR;	  	
}


static ngx_int_t 
ngx_http_limit_qps_watch_mode (ngx_http_request_t *r, ngx_http_variable_value_t *server_name_vv)
{	
	  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "[limit_qps_watch_mode]: pass");
	  return NGX_DECLINED; 
}


static ngx_int_t 
ngx_http_limit_qps_random_mode (ngx_http_request_t *r, ngx_http_variable_value_t *server_name_vv)
{
	  ngx_http_limit_qps_conf_t *lqcf;
	  	  
	  lqcf = ngx_http_get_module_main_conf(r, ngx_http_limit_qps_module);
	  
	  if (server_name_vv == NULL){
	      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "[limit_qps_random_mode]: forbidden, server is unknow");
	      return lqcf->forbidden_status_code;	    	
	  }
	  	  
	  if (ngx_http_limit_qps_find_manage_server(lqcf, server_name_vv) == NGX_OK){
	      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "[limit_qps_random_mode]: pass, server is manager");  
        return NGX_DECLINED;                    
	  }
	  	
	  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "[limit_qps_random_mode]: forbidden, server is not manager");
	  return lqcf->forbidden_status_code; 
}


static ngx_int_t 
ngx_http_limit_qps_protect_mode (ngx_http_request_t *r, ngx_http_variable_value_t *server_name_vv)
{
	  ngx_http_limit_qps_conf_t *lqcf;
	  
	  lqcf = ngx_http_get_module_main_conf(r, ngx_http_limit_qps_module);
	  
	  if (server_name_vv == NULL){
	      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "[limit_qps_protect_mode]: forbidden, server is unknow");
	      return lqcf->forbidden_status_code;	    	
	  }
	  	  
	  if (ngx_http_limit_qps_find_manage_server(lqcf, server_name_vv) == NGX_OK){
	      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "[limit_qps_protect_mode]: pass, server is manager"); 
        return NGX_DECLINED;                       
	  }
	  
	  if (ngx_http_limit_qps_list_find_protect_server(lqcf, server_name_vv) == NGX_OK){
	      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "[limit_qps_protect_mode]: pass, server = %v", server_name_vv);
        return NGX_DECLINED;                  	      	
	  }
	 	                            
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "[limit_qps_protect_mode]: forbidden, server = %v", server_name_vv);                      
	  return lqcf->forbidden_status_code;  
}


static ngx_int_t
ngx_http_limit_qps_lookup(ngx_http_request_t *r, ngx_http_limit_qps_conf_t *lqcf, ngx_http_limit_qps_server_shm_t *server_shm)
{
    ngx_int_t            excess;
    ngx_time_t          *tp;
    ngx_msec_t           now;
    ngx_msec_int_t       ms;
    
    if (server_shm->max <= 0){
        return NGX_DECLINED;    	
    }
    
    tp = ngx_timeofday();
    now = (ngx_msec_t) (tp->sec * 1000 + tp->msec);
    ms = (ngx_msec_int_t) (now - server_shm->last);   
    ms = ngx_abs(ms);    
    
    ngx_spinlock(&server_shm->lock, server_shm->lock_value, 1024);
    server_shm->real_count += 1;
    
    if (server_shm->freeze){
        if (ms >= lqcf->interval){
            server_shm->last = now;
            server_shm->count = 0;
            server_shm->freeze = 0;
            server_shm->limit_count += 1;
             
            ngx_http_limit_qps_spinunlock(&server_shm->lock, server_shm->lock_value);
            
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, 
                     "[limit_qps_lookup_awake]: server = %v, ms = %d, interval = %d", &server_shm->server_name, ms, lqcf->interval);
                      
            return NGX_DECLINED;
        }else{
        	  ngx_http_limit_qps_spinunlock(&server_shm->lock, server_shm->lock_value);
        	  
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, 
                     "[limit_qps_lookup_BUSYing]: server = %v, ms = %d, interval = %d", &server_shm->server_name, ms, lqcf->interval); 
                     
    	    	return NGX_BUSY;
        }    	
    }
    
    excess = server_shm->count - server_shm->max;
                                 
    if (ms < (ngx_msec_int_t) lqcf->interval){
        if (excess <= 0){
            server_shm->limit_count += 1;
            server_shm->count += 1;
            server_shm->freeze = 0;    	
        }	else{
            server_shm->freeze = 1;
            
            ngx_http_limit_qps_spinunlock(&server_shm->lock, server_shm->lock_value);
                
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, 
                     "[limit_qps_lookup_BUSY]: server = %v, ms = %d, excess = %d", &server_shm->server_name, ms, excess); 
                
            return NGX_BUSY;		
        }
    }else{
        server_shm->last = now;
        server_shm->count = 0;
        server_shm->freeze = 0;       
        server_shm->limit_count += 1; 	
    }
    
    ngx_http_limit_qps_spinunlock(&server_shm->lock, server_shm->lock_value);   
         
    return NGX_DECLINED;	  
}


static ngx_int_t
ngx_http_limit_qps_handler(ngx_http_request_t *r)
{
	  ngx_int_t                        rc;
	  ngx_http_limit_qps_conf_t        *lqcf;
	  ngx_http_limit_qps_servers_shm_t *servers_shm;
	  ngx_http_limit_qps_server_shm_t  *server_shm;
	  ngx_http_variable_value_t        *server_name_vv, *server_weight_vv;
	  ngx_uint_t                       *server_index;
	  ssize_t                          server_weight;
	  
	  if (r->main->limit_qps_set) {
        return NGX_DECLINED;
    }
    r->main->limit_qps_set = 1;
       	  	   
	  lqcf = ngx_http_get_module_main_conf(r, ngx_http_limit_qps_module); 
	  if (!lqcf->enable) {
	      return NGX_DECLINED;	
	  }
	  	  	  
	  if (lqcf->max <= 0) {
	      return NGX_DECLINED;	
	  }
	  
	  if (!lqcf->handler){
	  	  return NGX_DECLINED;
	  }
	  
	  servers_shm = lqcf->servers_shm;
	  server_index = NULL;
	    
	  /*
	   *Only total
	  */  
	  server_name_vv = ngx_http_get_indexed_variable(r, lqcf->server_name_index);
	  if (server_name_vv == NULL || server_name_vv->not_found){
	  	  goto total_handler;
	  }
	  
	  if (server_name_vv->len == 0){
	  	  goto total_handler;
	  }
	  
	  if (server_name_vv->len > 65535){
	  	  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "the value of the \"%V\" variable "
                          "is more than 65535 bytes: \"%v\"",
                          &lqcf->server_name_var, server_name_vv);
        goto total_handler;               
	  }	
	  
	  if (lqcf->server_weight_var.len != 0){	  
	      server_weight_vv = ngx_http_get_indexed_variable(r, lqcf->server_weight_index);
	  
	      if (server_weight_vv == NULL || server_weight_vv->not_found){
            goto total_handler;
        }
      
        if (server_weight_vv->len == 0){
            goto total_handler;
        }
      
        if (server_weight_vv->len > 65535){
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "the value of the \"%V\" variable "
                          "is more than 65535 bytes: \"%v\"",
                          &lqcf->server_weight_var, server_weight_vv);
            goto total_handler;               
        }
                
        server_weight = ngx_atosz(server_weight_vv->data, server_weight_vv->len);
        if (server_weight == NGX_ERROR){
	          goto total_handler; 	
	      }
    }else{
    	  server_weight = lqcf->server_default_weight;
    }
    /*
	   *Diff Service
	  */         
    //TOTAL
    server_shm = &servers_shm->server[lqcf->server_number-1];   
	  rc = ngx_http_limit_qps_lookup(r, lqcf, server_shm);
	  if (rc == NGX_BUSY){
	      rc = lqcf->handler(r, server_name_vv);	        	
	  }
	  
	  if (rc != NGX_DECLINED){
	  	  return rc;
	  }
	  
	  //service	
	  server_index = ngx_http_limit_qps_hash_find_server_index(lqcf, server_name_vv);   
	  if (server_index == NULL){
    	  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "[ngx_http_limit_qps_handler]: Can not find the index of the '%v'",
                          server_name_vv);
        return NGX_DECLINED;  	
    }
                               
    if (*server_index >= lqcf->server_number){
    	  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "[ngx_http_limit_qps_handler]: server_index = %ui, server_number = %ui",
                          *server_index, lqcf->server_number);
        return NGX_DECLINED;	
    }
       
    server_shm = &servers_shm->server[*server_index];
	  server_shm->max = server_weight;
	  ngx_http_limit_qps_lookup(r, lqcf, server_shm); 
	  
	  return NGX_DECLINED;	
    
total_handler:
	  server_shm = &servers_shm->server[lqcf->server_number-1];
	  
    rc = ngx_http_limit_qps_lookup(r, lqcf, server_shm);
    if (rc == NGX_BUSY){
        rc = lqcf->handler(r, NULL);	
        return rc;
    }
    
    return NGX_DECLINED;
}


static ngx_int_t 
ngx_http_limit_qps_status_handler(ngx_http_request_t *r)
{
	  size_t                           buffer_size;
	  ngx_int_t                        i, rc;
	  ngx_buf_t                        *b;
	  ngx_chain_t                      out;
	  
	  ngx_http_limit_qps_conf_t        *lqcf;
	  ngx_http_limit_qps_servers_shm_t *servers_shm;
	  ngx_http_limit_qps_server_shm_t  *server_shm;
	  
	  if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }
	  
	  rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }
    
    r->headers_out.content_type.len = sizeof("text/html; charset=utf-8") - 1;
    r->headers_out.content_type.data = (u_char *) "text/html; charset=utf-8";
    
    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }
	  
	  lqcf = ngx_http_get_module_main_conf(r, ngx_http_limit_qps_module); 
	  if (!lqcf->enable) {
	  	  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "[ngx_http_limit_qps_status_handler]: The module is disabled");
	      return NGX_HTTP_INTERNAL_SERVER_ERROR;	
	  }
	  
	  buffer_size = lqcf->server_number * ngx_pagesize / 4;
    buffer_size = ngx_align(buffer_size, ngx_pagesize) + ngx_pagesize;
    b = ngx_create_temp_buf(r->pool, buffer_size);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    out.buf = b;
    out.next = NULL;
    
    b->last = ngx_snprintf(b->last, b->end - b->last,
        "{\n  \"title\":\"ngx_http_limit_qps_module\",\n  "
            "\"server_number\":\"%ui\",\n  "
            "\"datalist\":[\n", lqcf->server_number);
	  
	  servers_shm = lqcf->servers_shm;
	  for (i=0; i<lqcf->server_number; i++){
	  	  server_shm = &servers_shm->server[i];
	  	  if (server_shm->server_name.len == 0){
	  	      continue;	
	  	  }
	  	  
	  	  if (i == lqcf->server_number - 1){
	  	  	  b->last = ngx_snprintf(b->last, b->end - b->last,
                            "\t{\"index\":\"%ui\","
                            "\"name\":\"%V\","
                            "\"real_count\":\"%ui\","
                            "\"limit_count\":\"%ui\""                            
                            "}\n",
		                  i,
                      &server_shm->server_name,
                      server_shm->real_count,
                      server_shm->limit_count);
	  	  }else{	  	 
	          b->last = ngx_snprintf(b->last, b->end - b->last,
                            "\t{\"index\":\"%ui\","
                            "\"name\":\"%V\","
                            "\"real_count\":\"%ui\","
                            "\"limit_count\":\"%ui\"" 
                            "},\n",
		                  i,
                      &server_shm->server_name,
                      server_shm->real_count,
                      server_shm->limit_count);
        }    	
	  }
    b->last = ngx_snprintf(b->last, b->end - b->last,
             "  ]\n}\n");
	  
	  r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


static ngx_int_t
ngx_http_limit_qps_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{	
    size_t                            size;
    ngx_uint_t                        i;
    ngx_str_t                         *servers_name;
        
    ngx_slab_pool_t                   *shpool;
	  ngx_http_limit_qps_conf_t         *lqcf;  
	  ngx_http_limit_qps_servers_shm_t  *servers_shm, *oservers_shm;
	  ngx_http_limit_qps_server_shm_t   *server_shm, *oserver_shm;
       	
	  lqcf = shm_zone->data;
    oservers_shm = data;
    	           
    /*
     *ngx_slab_alloc new shared memory
    */
    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    size = sizeof(*servers_shm) + (lqcf->server_number - 1) * sizeof(ngx_http_limit_qps_server_shm_t);  
    servers_shm = ngx_slab_alloc(shpool, size);
    if (servers_shm == NULL) {
        goto failure;
    }
    ngx_memzero(servers_shm, size);
      
    
    /*
     *set servers_shm between old and new shared memory
    */
    servers_name = lqcf->servers_name;
    for (i=0; i<lqcf->server_number; i++){
	  	  server_shm = &servers_shm->server[i];
	  	  server_shm->server_index = i;
	  	  server_shm->freeze = 0;
	  	  server_shm->lock_value = 1;
	  	  
	  	  if (servers_name[i].len > 0){	  	  	  
	  	  	  server_shm->server_name.len = servers_name[i].len;
	  	      server_shm->server_name.data = ngx_slab_alloc(shpool, servers_name[i].len);
	  	      
	  	      memcpy(server_shm->server_name.data, servers_name[i].data, servers_name[i].len);	  	      
	  	  }else{
	  	  	  server_shm->server_name.data = NULL;
	  	      server_shm->server_name.len = 0;
	  	      continue;
	  	  }
	  	  
	  	  if (oservers_shm){
	  	      oserver_shm = ngx_http_limit_qps_find_server_shm((ngx_http_limit_qps_conf_t *)oservers_shm, &server_shm->server_name);
	  	      if (oserver_shm){	  	      	 
	  	         server_shm->last = oserver_shm->last;
	  	         server_shm->freeze = oserver_shm->freeze;
	  	         server_shm->real_count = oserver_shm->real_count;
	  	         server_shm->limit_count = oserver_shm->limit_count;		  	         
	  	         server_shm->count = oserver_shm->count;	  	         
	  	         server_shm->max = oserver_shm->max;	  	         
	  	      }
	  	  }	  	  	  	 	  	  
	  }
	  server_shm = &servers_shm->server[lqcf->server_number - 1];
	  server_shm->max = lqcf->max;	
	        
	  lqcf->servers_shm = servers_shm;
	  	  
    return NGX_OK;
    
failure:
    ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                  "ngx_http_limit_qps_init_zone size is too small, "
                  "you should specify a larger size.");
    return NGX_ERROR;
    
}


static ngx_int_t
ngx_http_limit_qps_init(ngx_conf_t *cf)
{
	  ngx_array_t                datas;
    ngx_hash_key_t             *hk;
    ngx_hash_init_t            hash;
    
    ngx_uint_t                 i, length;
	  ngx_http_handler_pt        *h;
	  ngx_http_core_main_conf_t  *cmcf;
	  ngx_http_core_srv_conf_t   **cscfp;
	  ngx_http_limit_qps_conf_t  *lqcf;

	  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);	  
    lqcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_limit_qps_module); 
    
    if (lqcf->hash_max_size == NGX_CONF_UNSET_UINT){
        lqcf->hash_max_size = 512;	
    }
    
    if (lqcf->hash_bucket_size == NGX_CONF_UNSET_UINT){
        lqcf->hash_bucket_size = 64;	
    }  
    	
    if (lqcf->forbidden_status_code == NGX_CONF_UNSET_UINT){
        lqcf->forbidden_status_code = NGX_HTTP_SERVICE_UNAVAILABLE;	
    }
   
    lqcf->server_number = cmcf->servers.nelts + 1;     
    lqcf->servers_name = ngx_pcalloc(cf->pool, lqcf->server_number * sizeof(ngx_str_t));
    if (lqcf->servers_name == NULL){
        return NGX_ERROR;	
    }
    
    if (ngx_array_init(&datas, cf->pool, lqcf->server_number, sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    
    cscfp = cmcf->servers.elts;
    for (i=0; i<lqcf->server_number - 1; i++){    	  
        if (cscfp[i]->server_name.len > 0){
        	  lqcf->servers_name[i] = cscfp[i]->server_name;
        	  	  	  	  	  	      
	  	      hk = ngx_array_push(&datas);
	  	      if (hk == NULL){
	  	          return NGX_ERROR;    	
	  	      }
	  	      hk->key = cscfp[i]->server_name;
	  	      hk->key_hash = ngx_hash_key_lc(cscfp[i]->server_name.data, cscfp[i]->server_name.len);
	  	      hk->value = ngx_pcalloc(cf->pool, sizeof(int));
	  	      *(ngx_uint_t *)hk->value = i;
	  	  }else{
	  	      lqcf->servers_name[i].data = NULL;		  	  	
	  	      lqcf->servers_name[i].len = 0;
	  	  }	
    }
    
    length = ngx_strlen("TOTAL");
    lqcf->servers_name[lqcf->server_number - 1].len = length;
    lqcf->servers_name[lqcf->server_number - 1].data = ngx_pcalloc(cf->pool, length);
    ngx_memcpy(lqcf->servers_name[lqcf->server_number - 1].data, "TOTAL", length);    
    hk = ngx_array_push(&datas);
	  if (hk == NULL){
	      return NGX_ERROR;    	
	  }
	  hk->key = lqcf->servers_name[lqcf->server_number - 1];
	  hk->key_hash = ngx_hash_key_lc(lqcf->servers_name[lqcf->server_number - 1].data, length);
	  hk->value = ngx_pcalloc(cf->pool, sizeof(int));
	  *(ngx_uint_t *)hk->value = lqcf->server_number - 1; 
    
    hash.hash = &lqcf->servers_in_hash;
	  hash.key = ngx_hash_key_lc;
    hash.max_size = lqcf->hash_max_size; 
    hash.bucket_size = lqcf->hash_bucket_size;
    hash.name = "limit_qps_servers_in_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, datas.elts, datas.nelts) != NGX_OK) {
        return NGX_ERROR;
    }
    
    /*
     * PREACCESS PHASE
    */    
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_limit_qps_handler;
    
    return NGX_OK;
}


static char *
ngx_http_limit_qps_set_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_limit_qps_status_handler;

    return NGX_CONF_OK;
}


static char *
ngx_http_limit_qps_protect_servers(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	  ngx_int_t                  i;
	  ngx_str_t                  *value, *protect_server;
	  
	  ngx_http_limit_qps_conf_t  *lqcf = conf;
	  
    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {	
        protect_server = ngx_list_push(lqcf->protect_servers);
        if (protect_server == NULL){
            return NGX_CONF_ERROR;	
        }
        protect_server->len = value[i].len;
        protect_server->data = value[i].data;         
    }
    
    return NGX_CONF_OK;
}


static char *
ngx_http_limit_qps(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{       
    u_char                    *p;           
    ngx_uint_t                 i, enable;
    ngx_str_t                  *value, s;   
    ssize_t                    zone_size;   
    ngx_str_t                  zone_name, *server_name, *server_weight;     
    ngx_shm_zone_t             *shm_zone;
    ngx_http_limit_qps_conf_t  *lqcf = conf;
    
    enable = 1; 
    zone_name.len = 0;
    zone_size = 0;   
    shm_zone = NULL;      
    server_name = NULL;
    server_weight = NULL;
       
    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "switch=", 7) == 0) {
            if (ngx_strncmp(value[i].data + 7, "on", value[i].len - 7) == 0){
                enable = 1;	           	
            }else if (ngx_strncmp(value[i].data + 7, "off", value[i].len - 7) == 0){
            	  enable = 0;	 
            }else{
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid parameter \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }
            continue;
        }
        
        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {
            zone_name.data = value[i].data + 5;

            p = (u_char *) ngx_strchr(zone_name.data, ':');
            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            zone_name.len = p - zone_name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            zone_size = ngx_parse_size(&s);
            if (zone_size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            if (zone_size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "zone \"%V\" is too small", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "interval=", 9) == 0) {
            s.data = value[i].data + 9;
            s.len = value[i].len - 9;
            
            lqcf->interval = ngx_parse_time(&s, 0);;
            if (lqcf->interval == NGX_ERROR) {
            	  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
                return NGX_ERROR;
            };
            continue;	
        }
        
        if (ngx_strncmp(value[i].data, "max=", 4) == 0) {
        	  s.data = value[i].data + 4;
            s.len = value[i].len - 4;
            
            lqcf->max = ngx_parse_size(&s);            
            if (lqcf->max == (size_t)NGX_ERROR) {
               ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid value \"%V\" ", &value[i]);
               return NGX_CONF_ERROR;
            }
            continue;
        }
        
        if (ngx_strncmp(value[i].data, "server=", 7) == 0) {
            s.data = value[i].data + 7;
            s.len = value[i].len - 7;
            
            if (s.data[0] == '$'){
            	  s.data++;
            	  s.len--;
                  
            	  lqcf->server_name_index = ngx_http_get_variable_index(cf, &s);
                if (lqcf->server_name_index == NGX_ERROR) {
              	    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid variable \"%V\" ", &value[i]);
                    return NGX_CONF_ERROR;
                }
                lqcf->server_name_var = s;
                continue;
            }
            
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }
        
        if (ngx_strncmp(value[i].data, "weight=", 7) == 0) {
            s.data = value[i].data + 7;
            s.len = value[i].len - 7;
            
            if (s.data[0] == '$'){
            	  s.data++;
            	  s.len--;
            	  
            	  lqcf->server_weight_index = ngx_http_get_variable_index(cf, &s);
                if (lqcf->server_weight_index == NGX_ERROR) {
              	    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid variable \"%V\" ", &value[i]);
                    return NGX_CONF_ERROR;
                }
                lqcf->server_weight_var = s;
                continue;
            }else{
            	  lqcf->server_weight_index = -1;
                lqcf->server_weight_var.len = 0;
                lqcf->server_default_weight	= ngx_atosz(s.data, s.len);
                if (lqcf->server_default_weight == NGX_ERROR){
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid size \"%V\" ", &value[i]);
                    return NGX_CONF_ERROR;
                }
                continue;
            }
                     
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
            return NGX_CONF_ERROR;        
        }
        
        if (ngx_strncmp(value[i].data, "action=", 7) == 0) {
            s.data = value[i].data + 7;
            s.len = value[i].len - 7;
            
            if (ngx_strncmp(s.data, "watch", s.len) == 0){
                lqcf->handler = ngx_http_limit_qps_watch_mode;
            }else if(ngx_strncmp(s.data, "random", s.len) == 0){
            	  lqcf->handler = ngx_http_limit_qps_random_mode;
            }else if(ngx_strncmp(s.data, "protect", s.len) == 0){
            	  lqcf->handler = ngx_http_limit_qps_protect_mode;
            }else{
            	  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
                return NGX_CONF_ERROR;          
            }
            continue;
        }
                      
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }
    
    //for ends
    lqcf->enable = enable;
       
    if (zone_name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &zone_name, zone_size,
                                     &ngx_http_limit_qps_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_limit_qps_init_zone;
    shm_zone->data = lqcf;
    
    return NGX_CONF_OK;
}


static void *
ngx_http_limit_qps_create_conf(ngx_conf_t *cf)
{
    ngx_http_limit_qps_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_qps_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    
    conf->enable = 0;
    conf->interval = 1000;        
                           
    conf->hash_max_size = NGX_CONF_UNSET_UINT;
    conf->hash_bucket_size = NGX_CONF_UNSET_UINT;
    conf->forbidden_status_code = NGX_CONF_UNSET_UINT;
    
    conf->server_name_index = -1;
    conf->server_weight_index = -1;
    conf->server_name_var.len = 0;
    conf->server_weight_var.len = 0;
    conf->server_default_weight = 1000;    
        
    conf->manager.len = 0;       
    conf->protect_servers = ngx_list_create(cf->pool, 4, sizeof(ngx_str_t));
    if (conf->protect_servers == NULL){
        return NULL;	
    }
    
    conf->handler = ngx_http_limit_qps_watch_mode;
        
    return conf;
}


