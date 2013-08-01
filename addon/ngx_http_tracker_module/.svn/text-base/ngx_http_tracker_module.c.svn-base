/*
 * nginx error log module, record the error number of error log.
 * author:	chen jie
 * modified:	2012-01-04
 * version:	0.1.0
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_atomic_t  *ngx_error_count = NULL;
static ngx_int_t ngx_tracker_flag = 0;

void ngx_http_tracker_add_error_count();
static ngx_int_t ngx_http_tracker_handler(ngx_http_request_t *r);
static char *ngx_http_tracker(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_tracker_init_zone(ngx_shm_zone_t *shm_zone, void *data);
static char * ngx_http_tracker_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_tracker_init(ngx_conf_t *cf);


static ngx_command_t ngx_http_tracker_commands[] = 
{ 
	{ ngx_string("tracker_zone"),
    NGX_HTTP_MAIN_CONF| NGX_CONF_TAKE1,
    ngx_http_tracker_zone,
    0,
    0,
    NULL 
  },

  { ngx_string("tracker"),
    NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
    ngx_http_tracker,
    0,
    0,
    NULL 
  },

  ngx_null_command
};


static ngx_http_module_t  ngx_http_tracker_module_ctx = 
{
  NULL,                             /* preconfiguration */
  ngx_http_tracker_init,            /* postconfiguration */

  NULL,                             /* create main configuration */
  NULL,                             /* init main configuration */

  NULL,                             /* create server configuration */
  NULL,                             /* merge server configuration */

  NULL,                             /* create location configration */
  NULL                              /* merge location configration */
};


ngx_module_t  ngx_http_tracker_module = {
  NGX_MODULE_V1,
  &ngx_http_tracker_module_ctx,          /* module context */
  ngx_http_tracker_commands,             /* module directives */
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


/*************************************************************************************
                            ngx_http_tracker_handler
***************************************************************************************/
void ngx_http_tracker_add_error_count()
{
	if (ngx_error_count == NULL){
	  return ;
	}
	
	(void) ngx_atomic_fetch_add(ngx_error_count, 1);

	return ;
}


static ngx_int_t ngx_http_tracker_handler(ngx_http_request_t *r)
{
  size_t             size;
  ngx_int_t          rc;
  ngx_buf_t         *b;
  ngx_chain_t        out;
  
  if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
    return NGX_HTTP_NOT_ALLOWED;
  }

  rc = ngx_http_discard_request_body(r);
  if (rc != NGX_OK) {
    return rc;
  }

  ngx_str_set(&r->headers_out.content_type, "text/plain");
  if (r->method == NGX_HTTP_HEAD) {
    r->headers_out.status = NGX_HTTP_OK;
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
      return rc;
    }
  }

  size = sizeof("Recent Error Counts:  \n") + NGX_ATOMIC_T_LEN;
  b = ngx_create_temp_buf(r->pool, size);
  if (b == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }
  
  out.buf = b;
  out.next = NULL;

  b->last = ngx_sprintf(b->last, "Recent Error Counts: %uA \n", *ngx_error_count);
  r->headers_out.status = NGX_HTTP_OK;
  r->headers_out.content_length_n = b->last - b->pos;
  b->last_buf = 1;
  
  rc = ngx_http_send_header(r);
  if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
    return rc;
  }

  return ngx_http_output_filter(r, &out);
}


static char *ngx_http_tracker(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_core_loc_conf_t  *clcf;

  clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
  if (ngx_tracker_flag == 1){
    clcf->handler = ngx_http_tracker_handler;
  }else{
  	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Tracker_zone must be configured");
  	return NGX_CONF_ERROR;
  }
  
  return NGX_CONF_OK;
}


static ngx_int_t ngx_http_tracker_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
  ngx_atomic_t  *octx = data;  
  ngx_atomic_t  *ctx  = shm_zone->data;;

  if (octx) {
    ctx = octx;
    return NGX_OK;
  }

  ngx_error_count = (ngx_atomic_t *) shm_zone->shm.addr;
  return NGX_OK;
}


static char * ngx_http_tracker_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  u_char      *p;
  ngx_uint_t  i;   
  size_t      size; 
  ngx_str_t   *value, name, s;
  ngx_shm_zone_t          *shm_zone;

  value = cf->args->elts;
  name.len = 0;
  size = 0;
  
  for (i=1; i < cf->args->nelts; i++) {
    if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {
      name.data = value[i].data + 5;
      p = (u_char *) ngx_strchr(name.data, ':');
      if (p) {
        *p = '\0';
        name.len = p - name.data;
        
        p++;
        s.len = value[i].data + value[i].len - p;
        s.data = p;
        size = ngx_parse_size(&s);
        if (size > 256) {
          continue;
        }
      }

      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid zone size \"%V\"", &value[i]);
      return NGX_CONF_ERROR;
    }
  }  //for ends

  if (name.len == 0 || size == 0) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" must have \"zone\" parameter", &cmd->name);
    return NGX_CONF_ERROR;
  }

  shm_zone = ngx_shared_memory_add(cf, &name, size, &ngx_http_tracker_module);
  if (shm_zone == NULL) {
    return NGX_CONF_ERROR;
  }

  if (shm_zone->data) {
    ngx_error_count = shm_zone->data;
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "tracker_zone \"%V\" is already bound", &value[1]);
    return NGX_CONF_ERROR;
  }

  ngx_tracker_flag = 1;
  shm_zone->init = ngx_http_tracker_init_zone;
  shm_zone->data = (void *)ngx_error_count;

  return NGX_CONF_OK;
}


static ngx_int_t ngx_http_tracker_init(ngx_conf_t *cf)
{
  ngx_tracker_flag = 0;
  return NGX_OK;
}



