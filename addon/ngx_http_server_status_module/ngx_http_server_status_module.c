
/*
 * Copyright (C) han.xiao
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define MAXSTRNUM	99
#define MAXSERVER	256
#define SHMSIZE		4096*100
#define SHMNAME		"server_status"
#define VERSION		"Spanner-status1.0.2\n\n"
#define PROTOCOLLEN	10


#define HTML_HEAD			"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\n"\
					        "\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n"\
					        "<html xmlns=\"http://www.w3.org/1999/xhtml\">\n"\
					        "<head>\n"\
					        "  <title>spanner</title>\n"\
					        "</head>\n"\
					        "<body>\n"

#define HTML_TAIL			"</body>\n"\
							"</html>\n"

#if (NGX_HTTP_SSL)

#define OUTPUTSTRSSL	"cache_name\tsize(byte)\tused\tsess_created\tsess_num"\
						"\tsess_removed\tsess_reused\n"
#define OUTPUTSTRSSL_VAR	"%*s\t%uz\t%uz\t%uA\t%uA\t%uA\t%uA\n"

#define OUTPUTSTRSSL_HTML	"<table border=\"1\">\n"\
					     	"  <tr>\n"\
					     	"    <th>cache_name</th>\n"\
					     	"    <th>size(byte)</th>\n"\
					     	"    <th>used</th>\n"\
					     	"    <th>sess_created</th>\n"\
					     	"    <th>sess_num</th>\n"\
					     	"    <th>sess_removed</th>\n"\
					     	"    <th>sess_reused</th>\n"\
					     	"  </tr>\n"
					        
#define OUTPUTSTRSSL_HTML_VAR	"  <tr>\n"\
								"	 <td>%*s</td>\n" \
								"	 <td>%uz</td>\n" \
								"	 <td>%uz</td>\n" \
								"	 <td>%uA</td>\n" \
								"	 <td>%uA</td>\n" \
								"	 <td>%uA</td>\n" \
								"	 <td>%uA</td>\n" \
								"  </tr>\n"
#endif


#if (NGX_HTTP_SSL)
#define OUTPUTSTRSERVER			"index\tserver_id\trequests\tpercent\thttp\thttps\tSSLV3\tSSLV2\tTLSV1\t200\t400\t302\t404\t304\t503\tothers"\
								"\tmax_reqtime" \
						        "\tmin_reqtime" \
						        "\tavg_reqtime" \
						        "\terrors\n" 

#define OUTPUTSTRSERVER_VAR		"%d\t%*s\t%uA\t%.2f%%\t%uA\t%uA\t%uA\t%uA\t%uA\t%uA\t%uA\t%uA\t%uA\t%uA\t%uA\t%uA\t%.3f\t%.3f\t%.3f\t%uA\n"

#define OUTPUTSTRSERVER_HTML	"<table border=\"1\">\n"\
								"  <tr>\n"\
						        "    <td>index</td>\n" \
						        "    <td>server_id</td>\n" \
						        "    <td>requests</td>\n" \
						        "    <td>percent</td>\n" \
						        "    <td>http</td>\n" \
						        "    <td>https</td>\n" \
						        "    <td>SSLV3</td>\n" \
						        "    <td>SSLV2</td>\n" \
						        "    <td>TLSV1</td>\n" \
						        "    <td>200</td>\n" \
						        "    <td>400</td>\n" \
						        "    <td>302</td>\n" \
						        "    <td>404</td>\n" \
						        "    <td>304</td>\n" \
						        "    <td>503</td>\n" \
						        "    <td>others</td>\n" \
						        "    <td>max_reqtime</td>\n" \
						        "    <td>min_reqtime</td>\n" \
						        "    <td>avg_reqtime</td>\n" \
						        "    <td>errors</td>\n" \
						        "  </tr>\n"



#define OUTPUTSTRSERVER_HTML_VAR	"  <tr>\n"\
									"    <td>%d</td>\n" \
							    	"    <td>%*s</td>\n" \
							    	"    <td>%uA</td>\n" \
							    	"    <td>%.2f%%</td>\n" \
							    	"    <td>%uA</td>\n" \
							    	"    <td>%uA</td>\n" \
							    	"    <td>%uA</td>\n" \
							    	"    <td>%uA</td>\n" \
							    	"    <td>%uA</td>\n" \
							    	"    <td>%uA</td>\n" \
							    	"    <td>%uA</td>\n" \
							    	"    <td>%uA</td>\n" \
							    	"    <td>%uA</td>\n" \
							    	"    <td>%uA</td>\n" \
							    	"    <td>%uA</td>\n" \
							    	"    <td>%uA</td>\n" \
							    	"    <td>%.3f</td>\n" \
							    	"    <td>%.3f</td>\n" \
							    	"    <td>%.3f</td>\n" \
							    	"    <td>%uA</td>\n" \
							    	"  </tr>\n"

#define TMP_OUTPUTSTRSERVER			"index\tserver_id\ttmp_requests\ttmp_percent\ttmp_http\ttmp_https\n"

#define TMP_OUTPUTSTRSERVER_VAR		"%d\t%*s\t%uA\t%.2f%%\t%uA\t%uA\n"

#define TMP_OUTPUTSTRSERVER_HTML	"<table border=\"1\">\n"\
									"  <tr>\n"\
							        "    <td>index</td>\n" \
							        "    <td>server_id</td>\n" \
							        "    <td>tmp_requests</td>\n" \
							        "    <td>tmp_percent</td>\n" \
							        "    <td>tmp_http</td>\n" \
							        "    <td>tmp_https</td>\n" \
							        "  </tr>\n"

#define TMP_OUTPUTSTRSERVER_HTML_VAR	"  <tr>\n"\
										"    <td>%d</td>\n" \
								    	"    <td>%*s</td>\n" \
								    	"    <td>%uA</td>\n" \
								    	"    <td>%.2f%%</td>\n" \
								    	"    <td>%uA</td>\n" \
								    	"    <td>%uA</td>\n" \
								    	"  </tr>\n"
							    	

#else

#define OUTPUTSTRSERVER			"index\tserver_id\trequests\tpercent\thttp\t200\t400\t302\t404\t304\t503\tothers"\
								"\tmax_reqtime" \
						        "\tmin_reqtime" \
						        "\tavg_reqtime" \
						        "\terrors\n"

#define OUTPUTSTRSERVER_VAR		"%d\t%*s\t%uA\t%.2f%%\t%uA\t%uA\t%uA\t%uA\t%uA\t%uA\t%uA\t%uA\t%.3f\t%.3f\t%.3f\t%uA\n"

#define OUTPUTSTRSERVER_HTML	"<table border=\"1\">\n"\
								"  <tr>\n"\
						        "    <td>index</td>\n" \
						        "    <td>server_id</td>\n" \
						        "    <td>requests</td>\n" \
						        "    <td>percent</td>\n" \
						        "    <td>http</td>\n" \
						        "    <td>200</td>\n" \
						        "    <td>400</td>\n" \
						        "    <td>302</td>\n" \
						        "    <td>404</td>\n" \
						        "    <td>304</td>\n" \
						        "    <td>503</td>\n" \
						        "    <td>others</td>\n" \
						        "    <td>max_reqtime</td>\n" \
						        "    <td>min_reqtime</td>\n" \
						        "    <td>avg_reqtime</td>\n" \
						        "    <td>errors</td>\n" \
						        "  </tr>\n"



#define OUTPUTSTRSERVER_HTML_VAR	"  <tr>\n"\
									"    <td>%d</td>\n" \
							    	"    <td>%*s</td>\n" \
							    	"    <td>%uA</td>\n" \
							    	"    <td>%.2f%%</td>\n" \
							    	"    <td>%uA</td>\n" \
							    	"    <td>%uA</td>\n" \
							    	"    <td>%uA</td>\n" \
							    	"    <td>%uA</td>\n" \
							    	"    <td>%uA</td>\n" \
							    	"    <td>%uA</td>\n" \
							    	"    <td>%uA</td>\n" \
							    	"    <td>%uA</td>\n" \
							    	"    <td>%.3f</td>\n" \
							    	"    <td>%.3f</td>\n" \
							    	"    <td>%.3f</td>\n" \
							    	"    <td>%uA</td>\n" \
							    	"  </tr>\n"


#endif

static char *ngx_http_stat(ngx_conf_t *cf,ngx_command_t *cmd,void *conf);
static char *ngx_http_server_id(ngx_conf_t *cf,ngx_command_t *cmd,void *conf);
static void *ngx_http_server_status_create_conf(ngx_conf_t *cf);
static void *ngx_http_server_status_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_server_status_zone(ngx_conf_t *cf, ngx_command_t *cmd,void *conf);
static char *ngx_http_server_status(ngx_conf_t *cf, ngx_command_t *cmd,void *conf);
static ngx_int_t ngx_http_server_status_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_server_status_reset_counter(ngx_http_request_t *r);
static ngx_int_t ngx_http_server_status_argscheck(ngx_http_request_t *r);
static ngx_int_t ngx_http_server_status_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_server_status_log_handler(ngx_http_request_t *r);

static ngx_uint_t					ngx_server_num = 0;
static u_char					ngx_server_id[MAXSERVER][MAXSTRNUM];
static ngx_http_core_srv_conf_t *ngx_srvid_cscf[MAXSERVER];
static ngx_uint_t out_servers = 0;
static ngx_uint_t tmp_servers = 0;
static ngx_uint_t out_sslcache = 0;
static ngx_uint_t out_html = 0;
static ngx_uint_t reset_counter = 0;
ngx_str_t	ngx_protocol_str;

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;

typedef struct
{
	ngx_uint_t	shm_index[MAXSERVER];
	u_char	server_id[MAXSERVER][MAXSTRNUM];
	ngx_uint_t	server_num;
	ngx_flag_t	flag[MAXSERVER];
}ngx_http_server_id_shm_map_t;

typedef struct
{
	ngx_uint_t  ngx_server_index;
	ngx_str_t	ngx_server_name;
	ngx_str_t	ngx_server_id;
	ngx_uint_t	shm_index;
	ngx_flag_t	flag;
}ngx_http_server_info_t;


typedef struct
{
	ngx_atomic_t	*http_requests;
#if (NGX_HTTP_SSL)
	ngx_atomic_t	*https_requests;
	ngx_atomic_t	*sslv3cnt;
	ngx_atomic_t	*sslv2cnt;
	ngx_atomic_t	*tlsv1cnt;

	ngx_atomic_t	*tmp_https_requests;
	ngx_atomic_t	*tmp_sslv3cnt;
	ngx_atomic_t	*tmp_sslv2cnt;
	ngx_atomic_t	*tmp_tlsv1cnt;
#endif

	ngx_atomic_t	*ok;
	ngx_atomic_t	*moved_temporarily;
	ngx_atomic_t	*not_modified;
	ngx_atomic_t	*bad_request;
	ngx_atomic_t	*not_found;
	ngx_atomic_t	*service_unavailable;
	ngx_atomic_t	*others;
	ngx_atomic_t  *errors;

	ngx_msec_int_t   *minreqms;
	ngx_atomic_t   *avgreqms;
	ngx_msec_int_t   *maxreqms;
	ngx_atomic_t   *sumreqms;

	ngx_atomic_t	*tmp_ok;
	ngx_atomic_t	*tmp_moved_temporarily;
	ngx_atomic_t	*tmp_not_modified;
	ngx_atomic_t	*tmp_bad_request;
	ngx_atomic_t	*tmp_not_found;
	ngx_atomic_t	*tmp_service_unavailable;
	ngx_atomic_t	*tmp_others;
	ngx_atomic_t  *tmp_errors;

	ngx_msec_int_t   *tmp_minreqms;
	ngx_atomic_t   *tmp_avgreqms;
	ngx_msec_int_t   *tmp_maxreqms;
	ngx_atomic_t   *tmp_sumreqms;
	
	ngx_atomic_t	*tmp_http_requests;


}ngx_http_server_status_shctx_t;

typedef struct
{
	ngx_http_server_status_shctx_t  *sh;
	ngx_slab_pool_t             *shpool;
} ngx_http_server_status_ctx_t;

typedef struct {
	ngx_flag_t                      enable;
} ngx_http_server_status_conf_t;

typedef struct {
	ngx_flag_t                      enable;
	ngx_shm_zone_t              *shm_zone;
} ngx_http_server_status_main_conf_t;

static ngx_http_server_info_t *ngx_http_server_info;
static ngx_http_server_id_shm_map_t	ngx_http_server_id_shm_map;	
#if (NGX_HTTP_SSL)	
static ngx_int_t ngx_http_server_status_output_ssl(ngx_buf_t *b,char *formats, ngx_http_server_status_ctx_t *ctx);
#endif
static void ngx_http_server_status_output_servers(ngx_buf_t *b,char *formats, ngx_http_server_status_ctx_t *ctx);
static void ngx_http_server_status_output_tmp_servers(ngx_buf_t *b,char *formats, ngx_http_server_status_ctx_t *ctx);

static ngx_command_t  ngx_http_server_status_commands[] = {

    { ngx_string("server_status_global"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_server_status_zone,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_server_status_main_conf_t, enable),
      NULL },

    { ngx_string("server_status"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_http_server_status,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_server_status_conf_t, enable),
      NULL },
      
    { ngx_string("server_id"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_server_id,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },
      
    { ngx_string("stat"),
      NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
      ngx_http_stat,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
      ngx_null_command
   
};


static ngx_http_module_t  ngx_http_server_status_module_ctx = {
	NULL,										/* preconfiguration */
	ngx_http_server_status_init,				/* postconfiguration */
	ngx_http_server_status_create_main_conf,	/* create main configuration */
	NULL,										/* init main configuration */
	ngx_http_server_status_create_conf,			/* create server configuration */
	NULL,										/* merge server configuration */
	NULL,										/* create location configration */
	NULL										/* merge location configration */
};


ngx_module_t  ngx_http_server_status_module = {
	NGX_MODULE_V1,
	&ngx_http_server_status_module_ctx,			/* module context */
	ngx_http_server_status_commands,			/* module directives */
	NGX_HTTP_MODULE,							/* module type */
	NULL,										/* init master */
	NULL,										/* init module */
	NULL,										/* init process */
	NULL,										/* init thread */
	NULL,										/* exit thread */
	NULL,										/* exit process */
	NULL,										/* exit master */
	NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_server_status_handler(ngx_http_request_t *r)
{
	ngx_uint_t					i;
	ngx_http_server_status_ctx_t   *ctx;
	ngx_http_server_status_conf_t  *lrcf;
	ngx_http_server_status_main_conf_t  *ssmf;
	ngx_http_core_main_conf_t *cmcf;
	ngx_http_core_srv_conf_t **cscfp;

	cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
	cscfp = cmcf->servers.elts;
	lrcf = ngx_http_get_module_srv_conf(r, ngx_http_server_status_module);

	ssmf = ngx_http_get_module_main_conf(r, ngx_http_server_status_module);
	if (ssmf->shm_zone == NULL) 
	{
		return NGX_DECLINED;
	}

	/* only count the server which server_status enable*/
	if(ssmf->enable)
	{
		if(NGX_CONF_UNSET == lrcf->enable || lrcf->enable)
		{

			ctx = ssmf->shm_zone->data;
			//ngx_shmtx_lock(&ctx->shpool->mutex);

			/* match */
			for(i = 0 ; i < ngx_server_num; i++)
			{
				if(ngx_http_server_info[i].ngx_server_id.len)
				{
				
#if (NGX_HTTP_SSL)

					if (cscfp[i] == *(r->srv_conf) && r->connection->ssl)
					{
						ngx_ssl_get_protocol(r->connection,r->pool,&ngx_protocol_str);
						if(!ngx_strncmp(ngx_protocol_str.data,"SSLv3",ngx_strlen("SSLv3")))
						{
							(void) ngx_atomic_fetch_add(
							&ctx->sh->sslv3cnt[ngx_http_server_info[i].shm_index],1);

							(void) ngx_atomic_fetch_add(
							&ctx->sh->tmp_sslv3cnt[ngx_http_server_info[i].shm_index],1);
						}
						else if(!ngx_strncmp(ngx_protocol_str.data,"SSLv2",ngx_strlen("SSLv3")))
						{
							(void) ngx_atomic_fetch_add(
							&ctx->sh->sslv2cnt[ngx_http_server_info[i].shm_index],1);

							(void) ngx_atomic_fetch_add(
							&ctx->sh->tmp_sslv2cnt[ngx_http_server_info[i].shm_index],1);
						}
						else if(!ngx_strncmp(ngx_protocol_str.data,"TLSv1",ngx_strlen("TLSv1")))
						{
							(void) ngx_atomic_fetch_add(
							&ctx->sh->tlsv1cnt[ngx_http_server_info[i].shm_index],1);

							(void) ngx_atomic_fetch_add(
							&ctx->sh->tmp_tlsv1cnt[ngx_http_server_info[i].shm_index],1);
						}
						(void) ngx_atomic_fetch_add(
						&ctx->sh->https_requests[ngx_http_server_info[i].shm_index],1);
						(void) ngx_atomic_fetch_add(
						&ctx->sh->tmp_https_requests[ngx_http_server_info[i].shm_index],1);
					}
					else
#endif
					if(cscfp[i] == *(r->srv_conf))
					{
						(void) ngx_atomic_fetch_add(
						&ctx->sh->http_requests[ngx_http_server_info[i].shm_index],1);
						(void) ngx_atomic_fetch_add(
						&ctx->sh->tmp_http_requests[ngx_http_server_info[i].shm_index],1);
					}
				}
			}
			//ngx_shmtx_unlock(&ctx->shpool->mutex);

		}
	}
	return NGX_DECLINED;
}



static ngx_int_t
ngx_http_server_status_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
 	ngx_http_server_status_ctx_t  *octx = data;
	ngx_http_server_status_ctx_t  *ctx;
	ngx_uint_t i;
	ctx = shm_zone->data;

	if (octx) 
	{
		ctx->sh = octx->sh;
		ctx->shpool = octx->shpool;
		return NGX_OK;
	}

    	ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

	if (shm_zone->shm.exists) 
	{
		ctx->sh = ctx->shpool->data;
		return NGX_OK;
	}

	ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_server_status_shctx_t));
	
	if (NULL == ctx->sh) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh ");
		return NGX_ERROR;
	}

	ctx->sh->http_requests = ngx_slab_alloc(ctx->shpool, MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->http_requests) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->http_requests");
		return NGX_ERROR;
	}
#if (NGX_HTTP_SSL)
	ctx->sh->https_requests = ngx_slab_alloc(ctx->shpool, MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->https_requests) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->https_requests");
		return NGX_ERROR;
	}

	ctx->sh->sslv3cnt = ngx_slab_alloc(ctx->shpool, MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->sslv3cnt) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->sslv3cnt");
		return NGX_ERROR;
	}

	ctx->sh->sslv2cnt = ngx_slab_alloc(ctx->shpool, MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->sslv2cnt) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->sslv2cnt");
		return NGX_ERROR;
	}

	ctx->sh->tlsv1cnt = ngx_slab_alloc(ctx->shpool, MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->tlsv1cnt) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->tlsv1cnt");
		return NGX_ERROR;
	}

	ctx->sh->tmp_sslv3cnt = ngx_slab_alloc(ctx->shpool, MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->tmp_sslv3cnt) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->tmp_sslv3cnt");
		return NGX_ERROR;
	}

	ctx->sh->tmp_sslv2cnt = ngx_slab_alloc(ctx->shpool, MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->tmp_sslv2cnt) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->tmp_sslv2cnt");
		return NGX_ERROR;
	}

	ctx->sh->tmp_tlsv1cnt = ngx_slab_alloc(ctx->shpool, MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->tmp_tlsv1cnt) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->tmp_tlsv1cnt");
		return NGX_ERROR;
	}
#endif

	ctx->sh->tmp_http_requests = ngx_slab_alloc(ctx->shpool, MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->tmp_http_requests) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->http_requests");
		return NGX_ERROR;
	}

	ctx->sh->ok= ngx_slab_alloc(ctx->shpool,MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->ok) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->ok");
		return NGX_ERROR;
	}

	ctx->sh->bad_request= ngx_slab_alloc(ctx->shpool,MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->bad_request) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->bad_request");
		return NGX_ERROR;
	}

	ctx->sh->moved_temporarily= ngx_slab_alloc(ctx->shpool,MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->moved_temporarily) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->moved_temporarily");
		return NGX_ERROR;
	}

	ctx->sh->not_found= ngx_slab_alloc(ctx->shpool,MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->not_found) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->not_found");
		return NGX_ERROR;
	}

	ctx->sh->not_modified= ngx_slab_alloc(ctx->shpool,MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->not_modified) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->not_modified");
		return NGX_ERROR;
	}

	ctx->sh->service_unavailable= ngx_slab_alloc(ctx->shpool,MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->service_unavailable) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->service_unavailable");
		return NGX_ERROR;
	}

	ctx->sh->others= ngx_slab_alloc(ctx->shpool,MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->others) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->others");
		return NGX_ERROR;
	}
	
	ctx->sh->errors= ngx_slab_alloc(ctx->shpool,MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->errors) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->errors");
		return NGX_ERROR;
	}

	ctx->sh->minreqms= ngx_slab_alloc(ctx->shpool,MAXSERVER * sizeof(ngx_msec_int_t));
	if (NULL == ctx->sh->minreqms) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->minreqms");
		return NGX_ERROR;
	}
	
	ctx->sh->avgreqms= ngx_slab_alloc(ctx->shpool,MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->avgreqms) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->avgreqms");
		return NGX_ERROR;
	}

	ctx->sh->maxreqms= ngx_slab_alloc(ctx->shpool,MAXSERVER * sizeof(ngx_msec_int_t));
	if (NULL == ctx->sh->maxreqms) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->maxreqms");
		return NGX_ERROR;
	}

	ctx->sh->sumreqms= ngx_slab_alloc(ctx->shpool,MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->sumreqms) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->sumreqms");
		return NGX_ERROR;
	}

	ctx->sh->tmp_ok= ngx_slab_alloc(ctx->shpool,MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->tmp_ok) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->tmp_ok");
		return NGX_ERROR;
	}

	ctx->sh->tmp_bad_request= ngx_slab_alloc(ctx->shpool,MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->tmp_bad_request) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->tmp_bad_request");
		return NGX_ERROR;
	}

	ctx->sh->tmp_moved_temporarily= ngx_slab_alloc(ctx->shpool,MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->tmp_moved_temporarily) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->tmp_moved_temporarily");
		return NGX_ERROR;
	}

	ctx->sh->tmp_not_found= ngx_slab_alloc(ctx->shpool,MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->tmp_not_found) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->tmp_not_found");
		return NGX_ERROR;
	}

	ctx->sh->tmp_not_modified= ngx_slab_alloc(ctx->shpool,MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->tmp_not_modified) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->tmp_not_modified");
		return NGX_ERROR;
	}

	ctx->sh->tmp_service_unavailable= ngx_slab_alloc(ctx->shpool,MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->tmp_service_unavailable) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->tmp_service_unavailable");
		return NGX_ERROR;
	}

	ctx->sh->tmp_others= ngx_slab_alloc(ctx->shpool,MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->tmp_others) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->tmp_others");
		return NGX_ERROR;
	}
	
	ctx->sh->tmp_errors= ngx_slab_alloc(ctx->shpool,MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->tmp_errors) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->errors");
		return NGX_ERROR;
	}

	ctx->sh->tmp_minreqms= ngx_slab_alloc(ctx->shpool,MAXSERVER * sizeof(ngx_msec_int_t));
	if (NULL == ctx->sh->tmp_minreqms) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->tmp_minreqms");
		return NGX_ERROR;
	}
	
	ctx->sh->tmp_avgreqms= ngx_slab_alloc(ctx->shpool,MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->tmp_avgreqms) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->tmp_avgreqms");
		return NGX_ERROR;
	}

	ctx->sh->tmp_maxreqms= ngx_slab_alloc(ctx->shpool,MAXSERVER * sizeof(ngx_msec_int_t));
	if (NULL == ctx->sh->tmp_maxreqms) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->tmp_maxreqms");
		return NGX_ERROR;
	}

	ctx->sh->tmp_sumreqms= ngx_slab_alloc(ctx->shpool,MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->tmp_sumreqms) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->tmp_sumreqms");
		return NGX_ERROR;
	}
	
#if (NGX_HTTP_SSL)
	ctx->sh->tmp_https_requests = ngx_slab_alloc(ctx->shpool, MAXSERVER * sizeof(ngx_atomic_t));
	if (NULL == ctx->sh->tmp_https_requests) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,shm_zone->shm.log, 0,
		"ngx_http_server_status_init_zone  NULL == ctx->sh->https_requests");
		return NGX_ERROR;
	}
#endif

	ctx->shpool->data = ctx->sh;
	for(i = 0 ; i < ngx_server_num; i++)
	{
		ctx->sh->minreqms[ngx_http_server_info[i].shm_index] = 0x7fffffff;
		ctx->sh->tmp_minreqms[ngx_http_server_info[i].shm_index] = 0x7fffffff;
	}

	return NGX_OK;
}



static void *
ngx_http_server_status_create_main_conf(ngx_conf_t *cf)
{
	ngx_http_server_status_main_conf_t  *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_server_status_main_conf_t));
	if (conf == NULL) 
	{
		return NULL;
	}

	conf->enable = NGX_CONF_UNSET;

	return conf;
}

static void *
ngx_http_server_status_create_conf(ngx_conf_t *cf)
{
	ngx_http_server_status_conf_t  *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_server_status_conf_t));
	if (conf == NULL) 
	{
		return NULL;
	}

	conf->enable = NGX_CONF_UNSET;
	return conf;
}


static char *
ngx_http_server_status_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	size_t                     size;
	ngx_str_t                 name;
	ngx_shm_zone_t            *shm_zone;
	ngx_http_server_status_ctx_t  *ctx;
	ngx_http_server_status_main_conf_t *ssmf = conf;
	char  *rv;

	ctx = NULL;
	rv = ngx_conf_set_flag_slot(cf, cmd, conf);
	if (rv != NGX_CONF_OK) 
	{
		return rv;
	}

	/* shm's name and size*/
	name.data = SHMNAME;
	name.len = ngx_strlen(SHMNAME);
	size = SHMSIZE;

	if (name.len == 0 || size == 0) 
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		"\"%V\" must have \"zone\" parameter",
		&cmd->name);
		return NGX_CONF_ERROR;
	}

	ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_server_status_ctx_t));
	if (ctx == NULL) 
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		"no variable is defined for server_status_zone \"%V\"",
		&cmd->name);
		return NGX_CONF_ERROR;
	}

	shm_zone = ngx_shared_memory_add(cf, &name, size,
				&ngx_http_server_status_module);
	if (shm_zone == NULL) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,cf->log, 0,
		"ngx_http_server_status_zone  shm_zone == NULL");
		return NGX_CONF_ERROR;
	}

	if (shm_zone->data) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP,cf->log, 0,
		"ngx_http_server_status_zone  shm_zone->data");
		ctx = shm_zone->data;
		return NGX_CONF_ERROR;
	}

	shm_zone->init = ngx_http_server_status_init_zone;
	shm_zone->data = ctx;
	ssmf->shm_zone = shm_zone;

	return NGX_CONF_OK;
}


static char *
ngx_http_server_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	char  *rv;

	rv = ngx_conf_set_flag_slot(cf, cmd, conf);
	if (rv != NGX_CONF_OK) {
	return rv;
	}
	return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_server_status_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt        *h;
	ngx_http_core_main_conf_t  *cmcf;
	ngx_http_core_srv_conf_t **cscfp;
	ngx_uint_t i,j;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
	ngx_server_num = cmcf->servers.nelts;

	ngx_protocol_str.data = ngx_palloc(cf->pool,PROTOCOLLEN);
	
	ngx_http_server_info = ngx_palloc(cf->pool, ngx_server_num * sizeof(ngx_http_server_info_t));
	if(NULL == ngx_http_server_info)
	{
		return NGX_ERROR;
	}
	cscfp = cmcf->servers.elts;

	for(i = 0; i < ngx_http_server_id_shm_map.server_num; i++)
	{
		ngx_http_server_id_shm_map.flag[i] = 0;
	}
	for(i = 0; i < ngx_server_num; i++)
	{
		ngx_http_server_info[i].ngx_server_id.data = ngx_palloc(cf->pool,MAXSTRNUM);
		ngx_http_server_info[i].ngx_server_id.len = 0;
		for(j = 0 ; j < ngx_server_num; j++)
		{
			if(NULL == ngx_srvid_cscf[j])
			{
				continue;
			}
			if(ngx_srvid_cscf[j] == cscfp[i])
			{
				ngx_memcpy(ngx_http_server_info[i].ngx_server_id.data,ngx_server_id[j],ngx_strlen(ngx_server_id[j]));
				ngx_http_server_info[i].ngx_server_id.len = ngx_strlen(ngx_server_id[j]);
			}
		}
	}
	for(i = 0; i < ngx_server_num; i++)
	{
		for(j =0 ; j < ngx_http_server_id_shm_map.server_num; j++)
		{
			if(ngx_http_server_info[i].ngx_server_id.len != ngx_strlen(ngx_http_server_id_shm_map.server_id[j]))
			{
				continue;
			}
			if(!ngx_strncmp(ngx_http_server_info[i].ngx_server_id.data,ngx_http_server_id_shm_map.server_id[j],
				ngx_http_server_info[i].ngx_server_id.len))
			{
				ngx_http_server_info[i].shm_index = ngx_http_server_id_shm_map.shm_index[j];
				if(ngx_http_server_id_shm_map.flag[j])
				{
					ngx_http_server_info[i].flag = 0;
				}
				else
				{
					ngx_http_server_id_shm_map.flag[j] = 1;
					ngx_http_server_info[i].flag = 1;
				}
				break;
			}
		}
		if(j == ngx_http_server_id_shm_map.server_num)
		{
			ngx_memcpy(ngx_http_server_id_shm_map.server_id[j],ngx_http_server_info[i].ngx_server_id.data,ngx_http_server_info[i].ngx_server_id.len);
			ngx_http_server_id_shm_map.shm_index[j] = j;
			ngx_http_server_info[i].shm_index = j;
			ngx_http_server_id_shm_map.server_num++;
			ngx_http_server_id_shm_map.flag[j] = 1;
			ngx_http_server_info[i].flag = 1;
		}
		ngx_http_server_info[i].ngx_server_index = i;
		ngx_http_server_info[i].ngx_server_name.data = ngx_palloc(cf->pool, cscfp[i]->server_name.len);
		if(NULL == ngx_http_server_info[i].ngx_server_name.data)
		{
			return NGX_ERROR;
		}
		ngx_memcpy(ngx_http_server_info[i].ngx_server_name.data,cscfp[i]->server_name.data,cscfp[i]->server_name.len);
		ngx_http_server_info[i].ngx_server_name.len = cscfp[i]->server_name.len;

	}

	ngx_http_next_header_filter = ngx_http_top_header_filter;
  ngx_http_top_header_filter = ngx_http_server_status_filter;
	
	h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
	if (h == NULL) 
	{
		return NGX_ERROR;
	}
	*h = ngx_http_server_status_handler;

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_server_status_log_handler;

	return NGX_OK;
}

static ngx_int_t
ngx_http_stat_handler(ngx_http_request_t *r)
{
	ngx_int_t rc;
	ngx_chain_t out;
	ngx_http_server_status_ctx_t *ctx;
	ngx_http_server_status_conf_t *sscf;
	ngx_http_server_status_main_conf_t *ssmf;
	size_t size;
	ngx_buf_t *b;
	
	char *format=NULL;
	out_servers = 0;
	tmp_servers = 0;
	out_sslcache = 0;
	out_html = 0;
	reset_counter = 0;

	if(!(r->method & (NGX_HTTP_HEAD | NGX_HTTP_GET )))
	{
		return NGX_HTTP_NOT_ALLOWED;
	}

	if (r->uri.data[r->uri.len - 1] == '/') 
	{
		return NGX_DECLINED;
	}

	rc = ngx_http_discard_request_body(r);
	if(rc != NGX_OK)
	{
		return rc;
	}

	if(NGX_HTTP_NOT_FOUND == ngx_http_server_status_argscheck(r))
	{
		return NGX_HTTP_NOT_FOUND;
	}
	if(out_html)
	{
		ngx_str_t str_tmp = ngx_string("text/html; charset=utf-8");
    	r->headers_out.content_type = str_tmp;
	}
	else
	{
		ngx_str_set(&r->headers_out.content_type,"text/plain");
	}

	if(NGX_HTTP_HEAD == r->method)
	{
		r->headers_out.status = NGX_HTTP_OK;
		rc = ngx_http_send_header(r);
		if(NGX_ERROR == rc || rc > NGX_OK || r->header_only)
		{
			return rc;
		}
	}

	sscf = ngx_http_get_module_srv_conf(r,ngx_http_server_status_module);

	ssmf = ngx_http_get_module_main_conf(r,ngx_http_server_status_module);
	if(NULL == ssmf->shm_zone)
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		"main conf has no shm");
		return rc;
	}
	
	size = (ngx_server_num*2) * (sizeof(OUTPUTSTRSERVER)
		   + 4*sizeof(ngx_atomic_t) + MAXSTRNUM + sizeof(double));
#if (NGX_HTTP_SSL)	
	size += ((ngx_server_num*2) * (sizeof(OUTPUTSTRSSL) + 6*sizeof(ngx_atomic_t) + MAXSTRNUM));
#endif
	b = ngx_create_temp_buf(r->pool,size);

	if(NULL == b)
	{
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	out.buf = b;
	out.next = NULL;
	ctx = ssmf->shm_zone->data;
	
	if(out_html)
	{
		b->last = ngx_sprintf(b->last,HTML_HEAD);
	}
	
	//ngx_shmtx_lock(&ctx->shpool->mutex);
	b->last = ngx_sprintf(b->last,VERSION);
	
#if (NGX_HTTP_SSL)	
	if(out_sslcache)
	{
		if(NGX_HTTP_NOT_FOUND == ngx_http_server_status_output_ssl(b,format,ctx))
		{
			return NGX_HTTP_NOT_FOUND;
		}
	}
#endif

	if(reset_counter)
	{
		if(NGX_HTTP_NOT_FOUND == ngx_http_server_status_reset_counter(r))
		{
			return NGX_HTTP_NOT_FOUND;
		}
	}
	if(tmp_servers)
	{
		ngx_http_server_status_output_tmp_servers(b,format,ctx);	
	}
	if(out_servers)
	{
		ngx_http_server_status_output_servers(b,format,ctx);
	}
	//ngx_shmtx_unlock(&ctx->shpool->mutex);

	if(out_html)
	{
		b->last = ngx_sprintf(b->last,HTML_TAIL);
	}

	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = b->last - b->pos;

	b->last_buf = 1;
	rc = ngx_http_send_header(r);
	
	if(rc != NGX_OK)
	{
		return rc;
	}

	return ngx_http_output_filter(r,&out);

}



static char *
ngx_http_stat(ngx_conf_t *cf,ngx_command_t *cmd,void *conf)
{
	ngx_http_core_loc_conf_t *clcf;
	clcf = ngx_http_conf_get_module_loc_conf(cf,ngx_http_core_module);
	clcf->handler = ngx_http_stat_handler;

	return NGX_CONF_OK;
}


static char *
ngx_http_server_id(ngx_conf_t *cf,ngx_command_t *cmd,void *conf)
{
	ngx_str_t                 *value;
	ngx_http_core_srv_conf_t *cscf;
	ngx_http_core_main_conf_t  *cmcf;
	cscf = ngx_http_conf_get_module_srv_conf(cf,ngx_http_core_module);
	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	value = cf->args->elts;

	ngx_srvid_cscf[cmcf->servers.nelts-1] = cscf;
	ngx_memcpy(ngx_server_id[cmcf->servers.nelts-1],value[1].data,value[1].len);
	ngx_server_id[cmcf->servers.nelts-1][value[1].len] = '\0';

	return NGX_CONF_OK;
}



static ngx_int_t ngx_http_server_status_reset_counter(ngx_http_request_t *r)
{
	ngx_http_server_status_ctx_t *ctx;
	ngx_http_server_status_main_conf_t *ssmf;
	ngx_uint_t	i;

	ssmf = ngx_http_get_module_main_conf(r,ngx_http_server_status_module);
	if(NULL == ssmf->shm_zone)
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		"main conf has no shm");
		return NGX_HTTP_NOT_FOUND;
	}
	ctx = ssmf->shm_zone->data;
	for(i = 0 ; i < MAXSERVER; i++)
	{
		(void) ngx_atomic_fetch_add(
		&ctx->sh->tmp_http_requests[i],-(ctx->sh->tmp_http_requests[i]));

		(void) ngx_atomic_fetch_add(
		&ctx->sh->tmp_ok[i],-(ctx->sh->tmp_ok[i]));

		(void) ngx_atomic_fetch_add(
		&ctx->sh->tmp_moved_temporarily[i],-(ctx->sh->tmp_moved_temporarily[i]));

		(void) ngx_atomic_fetch_add(
		&ctx->sh->tmp_not_modified[i],-(ctx->sh->tmp_not_modified[i]));

		(void) ngx_atomic_fetch_add(
		&ctx->sh->tmp_bad_request[i],-(ctx->sh->tmp_bad_request[i]));

		(void) ngx_atomic_fetch_add(
		&ctx->sh->tmp_not_found[i],-(ctx->sh->tmp_not_found[i]));

		(void) ngx_atomic_fetch_add(
		&ctx->sh->tmp_service_unavailable[i],-(ctx->sh->tmp_service_unavailable[i]));

		(void) ngx_atomic_fetch_add(
		&ctx->sh->tmp_others[i],-(ctx->sh->tmp_others[i]));
		
		(void) ngx_atomic_fetch_add(
		&ctx->sh->tmp_errors[i],-(ctx->sh->tmp_errors[i]));

		(void) ngx_atomic_fetch_add(
		&ctx->sh->tmp_sumreqms[i],-(ctx->sh->tmp_sumreqms[i]));

		(void) ngx_atomic_fetch_add(
		&ctx->sh->tmp_maxreqms[i],-(ctx->sh->tmp_maxreqms[i]));

		(void) ngx_atomic_fetch_add(
		&ctx->sh->tmp_minreqms[i],-(ctx->sh->tmp_minreqms[i]));
#if (NGX_HTTP_SSL)	
		(void) ngx_atomic_fetch_add(
		&ctx->sh->tmp_https_requests[i],-(ctx->sh->tmp_https_requests[i]));

		(void) ngx_atomic_fetch_add(
		&ctx->sh->tmp_sslv3cnt[i],-(ctx->sh->tmp_sslv3cnt[i]));

		(void) ngx_atomic_fetch_add(
		&ctx->sh->tmp_sslv2cnt[i],-(ctx->sh->tmp_sslv2cnt[i]));

		(void) ngx_atomic_fetch_add(
		&ctx->sh->tmp_tlsv1cnt[i],-(ctx->sh->tmp_tlsv1cnt[i]));
#endif
	}
	return NGX_OK;
}


static ngx_int_t ngx_http_server_status_argscheck(ngx_http_request_t *r)
{
	
	ngx_str_t	value;

	if(r->args.len)
	{
		if (ngx_http_arg(r, (u_char *) "show", 4, &value) == NGX_OK) 
		{
			if(!ngx_strncmp("servers",value.data,ngx_strlen("servers")))
			{
				out_servers = 1 ;	
			}
			else if(!ngx_strncmp("tmp_servers",value.data,ngx_strlen("tmp_servers")))
			{
				tmp_servers = 1 ;
			}
#if (NGX_HTTP_SSL)	
			else if(!ngx_strncmp("sslcache",value.data,ngx_strlen("sslcache")))
			{
				out_sslcache = 1;	
			}
#endif

		}
		if (ngx_http_arg(r, (u_char *) "html", 4, &value) == NGX_OK) 
		{
			if(!ngx_strncmp("true",value.data,ngx_strlen("true")))
			{
				out_html = 1 ;		
			}
		}

		if (ngx_http_arg(r, (u_char *) "action", 6, &value) == NGX_OK) 
		{
			if(!ngx_strncmp("reset_counter",value.data,ngx_strlen("reset_counter")))
			{
				reset_counter = 1 ;		
			}
		}

		if(0 == (out_servers || out_sslcache || out_html || reset_counter || tmp_servers))
		{
			return NGX_HTTP_NOT_FOUND;
		}

		if((0 == (out_servers || out_sslcache || tmp_servers)) && (out_html || reset_counter))
		{
			out_servers = 1;
#if (NGX_HTTP_SSL)	
			out_sslcache = 1;
#endif
		}
	}
	else
	{
		out_servers = 1;
#if (NGX_HTTP_SSL)	
		out_sslcache = 1;
#endif
	}
	return NGX_OK;
}

static void ngx_http_server_status_output_servers(ngx_buf_t *b,char *format,ngx_http_server_status_ctx_t *ctx)
{
	ngx_uint_t i;
	ngx_atomic_t ngx_sum_requests = 0;
	double request_per = 0.0;
	double ngx_avg_reqtime = 0;

	for(i = 0; i < ngx_server_num; i++)
	{	
		if(ngx_http_server_info[i].flag)
		ngx_sum_requests += (ctx->sh->http_requests[ngx_http_server_info[i].shm_index]
#if (NGX_HTTP_SSL)		
		+ctx->sh->https_requests[ngx_http_server_info[i].shm_index]
#endif
		);
	}

	if(out_servers && out_sslcache)
	{
		b->last = ngx_cpymem(b->last,"\n",sizeof("\n")-1);
	}

	if(out_html)
	{
		format = OUTPUTSTRSERVER_HTML;
	}
	else
	{
		format = OUTPUTSTRSERVER;
	}
	b->last = ngx_cpymem(b->last,format,ngx_strlen(format));

	for(i = 0; i < ngx_server_num; i++)
	{	
		ngx_avg_reqtime = 0.0;
		if(!ngx_http_server_info[i].flag)
		{
			continue;
		}
		if(ngx_sum_requests)
		{
			request_per = ((double)(ctx->sh->http_requests[ngx_http_server_info[i].shm_index]
#if (NGX_HTTP_SSL)	 
			+ctx->sh->https_requests[ngx_http_server_info[i].shm_index]
#endif
			))

			/ngx_sum_requests*100;
		}

		if(ctx->sh->http_requests[ngx_http_server_info[i].shm_index]
#if (NGX_HTTP_SSL)						
	 	+ctx->sh->https_requests[ngx_http_server_info[i].shm_index]
#endif
		)
		{
			ngx_avg_reqtime = (double)(ctx->sh->sumreqms[ngx_http_server_info[i].shm_index]/
			(ctx->sh->http_requests[ngx_http_server_info[i].shm_index]
#if (NGX_HTTP_SSL)						
			+ctx->sh->https_requests[ngx_http_server_info[i].shm_index]
#endif
			));
		}
		
		if(NULL == ngx_http_server_info[i].ngx_server_id.data)
		{
			ngx_http_server_info[i].ngx_server_id.data = "";
			ngx_http_server_info[i].ngx_server_id.len = 0;
		}

		if(out_html)
		{
			format = OUTPUTSTRSERVER_HTML_VAR;
		}
		else
		{
			format = OUTPUTSTRSERVER_VAR;
		}
		
		b->last = ngx_sprintf(b->last,format,
		ngx_http_server_info[i].ngx_server_index,
		ngx_http_server_info[i].ngx_server_id.len,
		ngx_http_server_info[i].ngx_server_id.data,
		ctx->sh->http_requests[ngx_http_server_info[i].shm_index]
#if (NGX_HTTP_SSL)						
		+ctx->sh->https_requests[ngx_http_server_info[i].shm_index]
#endif						
		,
		request_per,ctx->sh->http_requests[ngx_http_server_info[i].shm_index]
#if (NGX_HTTP_SSL)	
		,ctx->sh->https_requests[ngx_http_server_info[i].shm_index]
		,ctx->sh->sslv3cnt[ngx_http_server_info[i].shm_index]
		,ctx->sh->sslv2cnt[ngx_http_server_info[i].shm_index]
		,ctx->sh->tlsv1cnt[ngx_http_server_info[i].shm_index]
#endif
		,ctx->sh->ok[ngx_http_server_info[i].shm_index]
		,ctx->sh->bad_request[ngx_http_server_info[i].shm_index]
		,ctx->sh->moved_temporarily[ngx_http_server_info[i].shm_index]
		,ctx->sh->not_found[ngx_http_server_info[i].shm_index]
		,ctx->sh->not_modified[ngx_http_server_info[i].shm_index]
		,ctx->sh->service_unavailable[ngx_http_server_info[i].shm_index]
		,ctx->sh->others[ngx_http_server_info[i].shm_index]
		,(double)(ctx->sh->maxreqms[ngx_http_server_info[i].shm_index])/1000
		,ctx->sh->minreqms[ngx_http_server_info[i].shm_index] == 0x7fffffff
		  ? 0.0:(double)(ctx->sh->minreqms[ngx_http_server_info[i].shm_index])/1000
		,ngx_avg_reqtime/1000
		,ctx->sh->errors[ngx_http_server_info[i].shm_index]
		);
	}
	
	if(out_html)
	{
		b->last = ngx_sprintf(b->last,"</table>\n");
	}
}


static void ngx_http_server_status_output_tmp_servers(ngx_buf_t *b,char *format,ngx_http_server_status_ctx_t *ctx)
{
	ngx_uint_t i;
	ngx_atomic_t ngx_sum_requests = 0;
	double request_per = 0.0;
	double ngx_avg_reqtime = 0;
	
	for(i = 0; i < ngx_server_num; i++)
	{	
		if(ngx_http_server_info[i].flag)
		ngx_sum_requests += (ctx->sh->tmp_http_requests[ngx_http_server_info[i].shm_index]
#if (NGX_HTTP_SSL)		
		+ctx->sh->tmp_https_requests[ngx_http_server_info[i].shm_index]
#endif
		);
	}

	if(tmp_servers && out_sslcache)
	{
		b->last = ngx_cpymem(b->last,"\n",sizeof("\n")-1);
	}

	if(out_html)
	{
		format = OUTPUTSTRSERVER_HTML;
	}
	else
	{
		format = OUTPUTSTRSERVER;
	}
	b->last = ngx_cpymem(b->last,format,ngx_strlen(format));

	for(i = 0; i < ngx_server_num; i++)
	{	
		ngx_avg_reqtime = 0.0;
		if(!ngx_http_server_info[i].flag)
		{
			continue;
		}
		if(ngx_sum_requests)
		{
			request_per = ((double)(ctx->sh->tmp_http_requests[ngx_http_server_info[i].shm_index]
#if (NGX_HTTP_SSL)	 
			+ctx->sh->tmp_https_requests[ngx_http_server_info[i].shm_index]
#endif
			))

			/ngx_sum_requests*100;
		}

		if(ctx->sh->tmp_http_requests[ngx_http_server_info[i].shm_index]
#if (NGX_HTTP_SSL)						
	 	+ctx->sh->tmp_https_requests[ngx_http_server_info[i].shm_index]
#endif
		)
		{
			ngx_avg_reqtime = (double)(ctx->sh->tmp_sumreqms[ngx_http_server_info[i].shm_index]/
			(ctx->sh->tmp_http_requests[ngx_http_server_info[i].shm_index]
#if (NGX_HTTP_SSL)						
			+ctx->sh->tmp_https_requests[ngx_http_server_info[i].shm_index]
#endif
			));
		}
		
		if(NULL == ngx_http_server_info[i].ngx_server_id.data)
		{
			ngx_http_server_info[i].ngx_server_id.data = "";
			ngx_http_server_info[i].ngx_server_id.len = 0;
		}

		if(out_html)
		{
			format = OUTPUTSTRSERVER_HTML_VAR;
		}
		else
		{
			format = OUTPUTSTRSERVER_VAR;
		}
		
		b->last = ngx_sprintf(b->last,format,
		ngx_http_server_info[i].ngx_server_index,
		ngx_http_server_info[i].ngx_server_id.len,
		ngx_http_server_info[i].ngx_server_id.data,
		ctx->sh->tmp_http_requests[ngx_http_server_info[i].shm_index]
#if (NGX_HTTP_SSL)						
		+ctx->sh->tmp_https_requests[ngx_http_server_info[i].shm_index]
#endif						
		,
		request_per,ctx->sh->tmp_http_requests[ngx_http_server_info[i].shm_index]
#if (NGX_HTTP_SSL)	
		,ctx->sh->tmp_https_requests[ngx_http_server_info[i].shm_index]
		,ctx->sh->tmp_sslv3cnt[ngx_http_server_info[i].shm_index]
		,ctx->sh->tmp_sslv2cnt[ngx_http_server_info[i].shm_index]
		,ctx->sh->tmp_tlsv1cnt[ngx_http_server_info[i].shm_index]
#endif
		,ctx->sh->tmp_ok[ngx_http_server_info[i].shm_index]
		,ctx->sh->tmp_bad_request[ngx_http_server_info[i].shm_index]
		,ctx->sh->tmp_moved_temporarily[ngx_http_server_info[i].shm_index]
		,ctx->sh->tmp_not_found[ngx_http_server_info[i].shm_index]
		,ctx->sh->tmp_not_modified[ngx_http_server_info[i].shm_index]
		,ctx->sh->tmp_service_unavailable[ngx_http_server_info[i].shm_index]
		,ctx->sh->tmp_others[ngx_http_server_info[i].shm_index]
		,(double)(ctx->sh->tmp_maxreqms[ngx_http_server_info[i].shm_index])/1000
		,ctx->sh->tmp_minreqms[ngx_http_server_info[i].shm_index] == 0x7fffffff
		  ? 0.0:(double)(ctx->sh->tmp_minreqms[ngx_http_server_info[i].shm_index])/1000
		,ngx_avg_reqtime/1000
		,ctx->sh->tmp_errors[ngx_http_server_info[i].shm_index]
		);
	}
	
	if(out_html)
	{
		b->last = ngx_sprintf(b->last,"</table>\n");
	}
}

#if (NGX_HTTP_SSL)	
static ngx_int_t ngx_http_server_status_output_ssl(ngx_buf_t *b,char *format,ngx_http_server_status_ctx_t *ctx)
{
	ngx_uint_t i;
	ngx_list_part_t  *part;
	ngx_shm_zone_t   *shm_zone;
	ngx_ssl_session_cache_t  *cache;
	part = &((ngx_cycle_t *)ngx_cycle)->shared_memory.part;

	if(NULL == part)
	{
		return NGX_HTTP_NOT_FOUND;
	}
	shm_zone = part->elts;
	if(NULL == shm_zone)
	{
		return NGX_HTTP_NOT_FOUND;
	}

	if(out_html)
	{
		format = OUTPUTSTRSSL_HTML;
	}
	else
	{
		format = OUTPUTSTRSSL;
	}
	b->last = ngx_cpymem(b->last,format,ngx_strlen(format));

	for (i = 0; /* void */ ; i++) 
	{
		if (i >= part->nelts) 
		{
			if (part->next == NULL) 
			{
				break;
			}
			part = part->next;
			shm_zone = part->elts;
			i = 0;
		}
		if (&ngx_http_ssl_module != shm_zone[i].tag) 
		{
			continue;
		}
		cache = shm_zone[i].data;

		if(out_html)
		{
			format = OUTPUTSTRSSL_HTML_VAR;
		}
		else
		{
			format = OUTPUTSTRSSL_VAR;
		}
		b->last = ngx_sprintf(b->last,format,
		shm_zone[i].shm.name.len,
		shm_zone[i].shm.name.data,
		shm_zone[i].shm.size,
		*cache->sci.ngx_ssl_cache_used,
		*cache->sci.ngx_ssl_session_created,
		*cache->sci.ngx_ssl_session_number,
		*cache->sci.ngx_ssl_session_removed,
		*cache->sci.ngx_ssl_session_reused);
	}
	if(out_html)
	{
		b->last = ngx_sprintf(b->last,"</table>\n");
	}
	return NGX_OK;
}
#endif



static ngx_int_t ngx_http_server_status_filter(ngx_http_request_t *r)
{
	ngx_uint_t                       status;
	ngx_http_server_status_main_conf_t  *ssmf;
	ngx_http_core_srv_conf_t **cscfp;
	ngx_http_core_main_conf_t *cmcf;
	ngx_uint_t					i;
	ngx_http_server_status_ctx_t   *ctx;
	ngx_http_server_status_conf_t  *lrcf;

	cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
	cscfp = cmcf->servers.elts;
	ssmf = ngx_http_get_module_main_conf(r, ngx_http_server_status_module);
	status = r->headers_out.status;
	lrcf = ngx_http_get_module_srv_conf(r, ngx_http_server_status_module);

	if (ssmf->shm_zone == NULL) 
	{
		return ngx_http_next_header_filter(r);
	}
	
	/* only count the server which server_status enable*/
	if(ssmf->enable)
	{
		if(NGX_CONF_UNSET == lrcf->enable || lrcf->enable)
		{

			ctx = ssmf->shm_zone->data;
			//ngx_shmtx_lock(&ctx->shpool->mutex);

			/* match */
			for(i = 0 ; i < ngx_server_num; i++)
			{
				if(ngx_http_server_info[i].ngx_server_id.len)
				{

					if (cscfp[i] == *(r->srv_conf))
					{						
						switch(status)
						{
							case NGX_HTTP_OK:
								(void) ngx_atomic_fetch_add(
								&ctx->sh->ok[ngx_http_server_info[i].shm_index],1);

								(void) ngx_atomic_fetch_add(
								&ctx->sh->tmp_ok[ngx_http_server_info[i].shm_index],1);
								break;
							case NGX_HTTP_MOVED_TEMPORARILY:
								(void) ngx_atomic_fetch_add(
								&ctx->sh->moved_temporarily[ngx_http_server_info[i].shm_index],1);

								(void) ngx_atomic_fetch_add(
								&ctx->sh->tmp_moved_temporarily[ngx_http_server_info[i].shm_index],1);
								break;
							case NGX_HTTP_NOT_MODIFIED:
								(void) ngx_atomic_fetch_add(
								&ctx->sh->not_modified[ngx_http_server_info[i].shm_index],1);

								(void) ngx_atomic_fetch_add(
								&ctx->sh->tmp_not_modified[ngx_http_server_info[i].shm_index],1);
								break;
							case NGX_HTTP_BAD_REQUEST:
								(void) ngx_atomic_fetch_add(
								&ctx->sh->bad_request[ngx_http_server_info[i].shm_index],1);

								(void) ngx_atomic_fetch_add(
								&ctx->sh->tmp_bad_request[ngx_http_server_info[i].shm_index],1);								
								break;
							case NGX_HTTP_NOT_FOUND:
								(void) ngx_atomic_fetch_add(
								&ctx->sh->not_found[ngx_http_server_info[i].shm_index],1);

								(void) ngx_atomic_fetch_add(
								&ctx->sh->tmp_not_found[ngx_http_server_info[i].shm_index],1);					
								break;
							case NGX_HTTP_SERVICE_UNAVAILABLE:
								(void) ngx_atomic_fetch_add(
								&ctx->sh->service_unavailable[ngx_http_server_info[i].shm_index],1);
								
								(void) ngx_atomic_fetch_add(
								&ctx->sh->tmp_service_unavailable[ngx_http_server_info[i].shm_index],1);
								
								break;
							default:
								(void) ngx_atomic_fetch_add(
								&ctx->sh->others[ngx_http_server_info[i].shm_index],1);

								(void) ngx_atomic_fetch_add(
								&ctx->sh->tmp_others[ngx_http_server_info[i].shm_index],1);							
								break;
						}
						
						if (status >= NGX_HTTP_BAD_REQUEST){
								(void) ngx_atomic_fetch_add(
								&ctx->sh->errors[ngx_http_server_info[i].shm_index],1);
								
								(void) ngx_atomic_fetch_add(
								&ctx->sh->tmp_errors[ngx_http_server_info[i].shm_index],1);							
						}
					}
				}
			}
			//ngx_shmtx_unlock(&ctx->shpool->mutex);

		}
	}
	return ngx_http_next_header_filter(r);
}

static ngx_int_t ngx_http_server_status_log_handler(ngx_http_request_t *r)
{
	ngx_time_t      *tp;
    ngx_msec_int_t   ms;
	ngx_http_server_status_main_conf_t  *ssmf;
	ngx_http_core_srv_conf_t **cscfp;
	ngx_http_core_main_conf_t *cmcf;
	ngx_uint_t					i;
	ngx_http_server_status_ctx_t   *ctx;
	ngx_http_server_status_conf_t  *lrcf;
	ngx_atomic_int_t temp_ms;

    tp = ngx_timeofday();

    ms = (ngx_msec_int_t)
             ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));

	ms = ngx_max(ms, 0);
	temp_ms = (ngx_atomic_int_t)ms;
	
	cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
	cscfp = cmcf->servers.elts;
	ssmf = ngx_http_get_module_main_conf(r, ngx_http_server_status_module);
	lrcf = ngx_http_get_module_srv_conf(r, ngx_http_server_status_module);

	if (ssmf->shm_zone == NULL) 
	{
		return NGX_ERROR;
	}


	/* only count the server which server_status enable*/
	if(ssmf->enable)
	{
		if(NGX_CONF_UNSET == lrcf->enable || lrcf->enable)
		{

			ctx = ssmf->shm_zone->data;
			//ngx_shmtx_lock(&ctx->shpool->mutex);

			/* match */
			for(i = 0 ; i < ngx_server_num; i++)
			{
				if(ngx_http_server_info[i].ngx_server_id.len)
				{

					if (cscfp[i] == *(r->srv_conf))
					{
						if(ms < ctx->sh->minreqms[ngx_http_server_info[i].shm_index])
						{
							ctx->sh->minreqms[ngx_http_server_info[i].shm_index] = ms;
						}
						if(ms < ctx->sh->tmp_minreqms[ngx_http_server_info[i].shm_index])
						{
							ctx->sh->tmp_minreqms[ngx_http_server_info[i].shm_index] = ms;
						}
						if(ms > ctx->sh->maxreqms[ngx_http_server_info[i].shm_index])
						{
							ctx->sh->maxreqms[ngx_http_server_info[i].shm_index] = ms;
						}
						if(ms > ctx->sh->tmp_maxreqms[ngx_http_server_info[i].shm_index])
						{
							ctx->sh->tmp_maxreqms[ngx_http_server_info[i].shm_index] = ms;
						}
						(void) ngx_atomic_fetch_add(
						&ctx->sh->sumreqms[ngx_http_server_info[i].shm_index],temp_ms);

						(void) ngx_atomic_fetch_add(
						&ctx->sh->tmp_sumreqms[ngx_http_server_info[i].shm_index],temp_ms);
					}
				}
			}
			//ngx_shmtx_unlock(&ctx->shpool->mutex);

		}
	}
	
	return NGX_OK;
}


