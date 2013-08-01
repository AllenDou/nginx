
/*
 * Copyright (C) Han.Xiao
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#define CONFNUM 60


#define HTML_HEAD			"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\n"\
					        "\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n"\
					        "<html xmlns=\"http://www.w3.org/1999/xhtml\">\n"\
					        "<head>\n"\
					        "  <title>spanner</title>\n"\
					        "</head>\n"\
					        "<body>\n"

#define HTML_TAIL			"</body>\n"\
							"</html>\n"


#define OUTPUT				"Index\t"\
							"Drop_per\t"\
				        	"Location\t"\
				        	"Accepted\t"\
				        	"Refused\t\n"

#define OUTPUT_VAR		    "%d\t" \
        					"%d%%\t" \
       					    "%*s\t" \
       		 				"%uA\t" \
       					    "%uA\t\n" 	

#define OUTPUT_FILE			"Index\t"\
					   		"file\n"

#define OUTPUT_FILE_VAR		"%d\t"\
        					"%*s\n"

#define OUTPUT_HTML			 "<table border=\"1\">\n"\
				        	"  <tr>\n"\
				       	 	"    <th>Index</th>\n"\
				        	"    <th>Drop_per</th>\n"\
				        	"    <th>Location</th>\n"\
				        	"    <th>Accepted</th>\n"\
				        	"    <th>Refused</th>\n"\
				        	"  </tr>\n";

#define OUTPUT_VAR_HTML		 "  <tr>\n"\
        					"    <td>%d</td>\n" \
        					"    <td>%d%%</td>\n" \
        					"    <td>%*s</td>\n" \
        					"    <td>%uA</td>\n" \
        					"    <td>%uA</td>\n" \
        					"  </tr>\n" 	

#define OUTPUT_FILE_HTML	 "<table border=\"1\">\n"\
				        	"  <tr>\n"\
				        	"    <th>Index</th>\n"\
				        	"    <th>file</th>\n"\
				        	"  </tr>\n"

#define OUTPUT_FILE_VAR_HTML	 "  <tr>\n"\
        						"    <td>%d</td>\n" \
        						"    <td>%*s</td>\n" \
        						"  </tr>\n"



static void *ngx_http_drop_request_create_conf(ngx_conf_t *cf);
static char *ngx_http_drop_request_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_drop_request(ngx_conf_t *cf, ngx_command_t *cmd,void *conf);
static ngx_int_t ngx_http_drop_request_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_drop_request_probability(ngx_uint_t per);
static ngx_int_t ngx_http_drop_request_preconfig(ngx_conf_t *cf);
static ngx_int_t
ngx_http_drop_request_init_zone(ngx_shm_zone_t *shm_zone, void *data);
static ngx_int_t ngx_http_drop_request_procinit(ngx_cycle_t *cycle);
static char *
ngx_http_drop_request_show(ngx_conf_t *cf,ngx_command_t *cmd,void *conf);
static ngx_int_t
ngx_http_drop_request_show_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_drop_request_isnum(ngx_str_t *name);
static ngx_int_t ngx_http_drop_request_argscheck(ngx_http_request_t *r);
static void	ngx_http_drop_request_modify(ngx_http_request_t *r);

static ngx_uint_t modify_flag = 0;
static ngx_uint_t index_flag = 0;
static ngx_int_t per_flag = 0;
static ngx_uint_t out_html = 0;


static ngx_uint_t	confnum;
static ngx_atomic_t	*ngx_accepted_cnt;
static ngx_atomic_t	*ngx_refused_cnt;

typedef struct {
	ngx_shm_zone_t     *shm_zone;
	ngx_uint_t          per;
} ngx_http_drop_request_loc_conf_t;

typedef struct {
    	ngx_atomic_t	accepted;
    	ngx_atomic_t	refused;
} ngx_http_drop_request_status_shm_t;

typedef struct {
	ngx_http_drop_request_loc_conf_t	*loc_conf;
	ngx_uint_t	index;
	ngx_uint_t	per;
	ngx_str_t	location;
	ngx_str_t	file;
	ngx_http_drop_request_status_shm_t	*shm;
} ngx_http_drop_request_status_t;

typedef struct {
	ngx_http_drop_request_loc_conf_t	*loc_conf;
	ngx_uint_t						index;
} ngx_http_drop_request_loc_shm_map_t;

static ngx_array_t	*ngx_http_drop_request_arr = NULL;
static ngx_array_t	*ngx_http_drop_request_loc_shm_map_arr = NULL;

#define ngx_http_drop_request_status \
  ((ngx_http_drop_request_status_t*) ngx_http_drop_request_arr->elts)

#define ngx_http_drop_request_loc_shm_map \
  ((ngx_http_drop_request_loc_shm_map_t*) ngx_http_drop_request_loc_shm_map_arr->elts)


static ngx_http_drop_request_status_shm_t *ngx_http_drop_request_shm;

static ngx_command_t  ngx_http_drop_request_commands[] = {

	{ ngx_string("drop_request"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF| NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
      	  ngx_http_drop_request,
      	  NGX_HTTP_LOC_CONF_OFFSET,
      	  0,
      	  NULL },

	{ ngx_string("drop_request_show"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
	  ngx_http_drop_request_show,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  0,
	  NULL },
	ngx_null_command
};


static ngx_http_module_t  ngx_http_drop_request_module_ctx = {
	ngx_http_drop_request_preconfig,			/* preconfiguration */
	ngx_http_drop_request_init,				/* postconfiguration */

	NULL,							/* create main configuration */
	NULL,							/* init main configuration */

	NULL,							/* create server configuration */
	NULL,							/* merge server configuration */

	ngx_http_drop_request_create_conf,			/* create location configration */
	ngx_http_drop_request_merge_conf			/* merge location configration */
};


ngx_module_t  ngx_http_drop_request_module = {
	NGX_MODULE_V1,
	&ngx_http_drop_request_module_ctx,	/* module context */
	ngx_http_drop_request_commands,         /* module directives */
	NGX_HTTP_MODULE,                       	/* module type */
	NULL,                                  	/* init master */
	NULL,                                  	/* init module */
	ngx_http_drop_request_procinit,		/* init process */
	NULL,                                  	/* init thread */
	NULL,                                  	/* exit thread */
	NULL,                                  	/* exit process */
	NULL,                                  	/* exit master */
	NGX_MODULE_V1_PADDING
};


static ngx_int_t ngx_http_drop_request_preconfig(ngx_conf_t *cf) 
{
	confnum = 0;
	ngx_http_drop_request_arr = ngx_array_create(cf->pool, 3*CONFNUM,
	sizeof(ngx_http_drop_request_status_t));
	if (ngx_http_drop_request_arr == NULL)
	{
		return NGX_ERROR;
	}

	ngx_http_drop_request_loc_shm_map_arr = ngx_array_create(cf->pool, 10*CONFNUM,
	sizeof(ngx_http_drop_request_loc_shm_map_t));
	if (ngx_http_drop_request_loc_shm_map_arr == NULL)
	{
		return NGX_ERROR;
	}

	return NGX_OK;
}

static ngx_int_t
ngx_http_drop_request_handler(ngx_http_request_t *r)
{
	ngx_http_drop_request_loc_conf_t     *ldlcf;
	ngx_http_core_loc_conf_t	*clcf;
	ngx_http_core_srv_conf_t	*cscf;
	ngx_uint_t						per;
	ngx_uint_t	i;
	ngx_http_drop_request_status_t *stat;
	ngx_http_drop_request_loc_shm_map_t	*maps;

	clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
	cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

	ngx_accepted_cnt = NULL;
	ngx_refused_cnt = NULL;
	per = 0;

	ldlcf = ngx_http_get_module_loc_conf(r, ngx_http_drop_request_module);
	//printf("drop_request_handler ldlcf: %p \n",ldlcf);
	//printf("per :%d \n",ldlcf->per);
	if (NGX_CONF_UNSET_UINT == ldlcf->per)
	{
		return NGX_DECLINED;
	}
	else
	{
		for(i = 0; i < ngx_http_drop_request_arr->nelts; i++)
		{
			stat = &ngx_http_drop_request_status[i];
			if(stat->loc_conf == ldlcf)
			{
				ngx_accepted_cnt = &stat->shm->accepted;
				ngx_refused_cnt = &stat->shm->refused;
				per = stat->loc_conf->per;
				break;
			}
		}
		if(NULL == ngx_accepted_cnt && NULL == ngx_refused_cnt)
		{
			for (i=0; i<ngx_http_drop_request_loc_shm_map_arr->nelts; i++)
			{
				maps =  &ngx_http_drop_request_loc_shm_map[i];
				if(maps->loc_conf == ldlcf)
				{
					stat = &ngx_http_drop_request_status[maps->index];
					ngx_accepted_cnt = &stat->shm->accepted;
					ngx_refused_cnt = &stat->shm->refused;
					per = maps->loc_conf->per;
					break;
				}
			}
		}
		if(NULL == ngx_accepted_cnt && NULL == ngx_refused_cnt)
		{
			return NGX_DECLINED;
		}
		//per = ldlcf->per;
	}

	//printf("per:%d\n",per);
	if(NGX_ERROR == ngx_http_drop_request_probability(per))
	{
		(void) ngx_atomic_fetch_add(ngx_refused_cnt,1);
		return NGX_HTTP_SERVICE_UNAVAILABLE;
	}
	(void) ngx_atomic_fetch_add(ngx_accepted_cnt,1);
	return NGX_DECLINED;
}


static void *
ngx_http_drop_request_create_conf(ngx_conf_t *cf)
{
	ngx_http_drop_request_loc_conf_t  *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_drop_request_loc_conf_t));
	if (conf == NULL) 
	{
        	return NULL;
    	}

    	conf->per = NGX_CONF_UNSET_UINT;
	//printf("create conf : %p\n",conf);
    	return conf;
}

static char *ngx_http_drop_request_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_drop_request_loc_conf_t *prev = parent;
	ngx_http_drop_request_loc_conf_t *conf = child;
	ngx_http_drop_request_status_t *stat;
	ngx_http_drop_request_loc_shm_map_t	*maps;
	ngx_http_drop_request_loc_shm_map_t	*tmp_maps;
	ngx_uint_t	i;

	//printf("conf:%p   pre:%p\n",conf,prev);
	ngx_conf_merge_uint_value(conf->per, prev->per, NGX_CONF_UNSET_UINT);

	for (i=0; i<ngx_http_drop_request_arr->nelts; i++)
	{
		stat = &ngx_http_drop_request_status[i];
		if(prev ==  stat->loc_conf)
		{
			maps = ngx_array_push(ngx_http_drop_request_loc_shm_map_arr);
			 if (maps == NULL) {
		        return NGX_CONF_ERROR;
		    }
			maps->loc_conf = conf;
			maps->index = i;
			break;
		}
	}

	if(i == ngx_http_drop_request_arr->nelts)
	{
		for (i=0; i<ngx_http_drop_request_loc_shm_map_arr->nelts; i++)
		{
			maps =  &ngx_http_drop_request_loc_shm_map[i];
			if(maps->loc_conf == prev)
			{
				tmp_maps = ngx_array_push(ngx_http_drop_request_loc_shm_map_arr);
				 if (tmp_maps == NULL) {
			        return NGX_CONF_ERROR;
			    }
				tmp_maps->loc_conf = conf;
				tmp_maps->index = maps->index;
				break;
			}
		}
	}

	return NGX_CONF_OK;
}


static char *
ngx_http_drop_request(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_str_t                  *value;
	ngx_http_drop_request_loc_conf_t	*ldlcf = conf;
	ngx_http_drop_request_status_t	*status;

	value = cf->args->elts;

	if (!ngx_http_drop_request_isnum(&value[1]))
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		"invalid variable name \"%V\"", &value[1]);
		return NGX_CONF_ERROR;
	}

	if(value[1].len == 2)
	{
		ldlcf->per = (value[1].data[0] - '0');
	}
	
	else if(value[1].len == 3)
	{
		ldlcf->per = (value[1].data[0] - '0') * 10 + (value[1].data[1] - '0');
	}

	else if(value[1].len == 4)
	{
		ldlcf->per = 100;
	}

	status = ngx_array_push(ngx_http_drop_request_arr);
	if (status == NULL)
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
      	"drop_request: status == NULL");
		return NGX_CONF_ERROR;
	}

	status->location.data = ngx_palloc(cf->pool, 255);
	if(NULL == status->location.data)
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
      	"drop_request: NULL == status->location.data");
		return NGX_CONF_ERROR;
	}

	status->file.data = ngx_palloc(cf->pool, 1000);
	if(NULL == status->file.data)
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
      	"drop_request: NULL == status->file.data");
		return NGX_CONF_ERROR;
	}
	
	status->index = confnum;
	status->loc_conf = ldlcf;
	status->per = ldlcf->per;
	ngx_memcpy(status->location.data,cf->conf_file->file.name.data,cf->conf_file->file.name.len);
	status->location.data[cf->conf_file->file.name.len] = '\0';
	ngx_sprintf(status->location.data+cf->conf_file->file.name.len,"  at %d line      ",cf->conf_file->line);
	status->location.len = cf->conf_file->file.name.len + ngx_strlen("  at %d line      ");
	ngx_memcpy(status->file.data,cf->conf_file->buffer->start,cf->conf_file->line * 40);
	status->file.len = cf->conf_file->line * 40;
	
	confnum++;

    	return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_drop_request_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt        *h;
	ngx_http_core_main_conf_t  *cmcf;
	ngx_str_t        *shm_name;
	ngx_shm_zone_t   *shm_zone;
    
	if (ngx_http_drop_request_arr->nelts == 0) 
	{
		ngx_http_drop_request_shm = NULL;
		return NGX_OK;
	}

	shm_name = ngx_palloc(cf->pool, sizeof *shm_name);
	shm_name->len = sizeof("http_drop_request") - 1;
	shm_name->data = (unsigned char *) "http_drop_request";

	shm_zone = ngx_shared_memory_add(cf, shm_name,
			ngx_pagesize * (ngx_http_drop_request_arr->nelts + 1),
			&ngx_http_drop_request_module);

	if (shm_zone == NULL) 
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
      	"drop_request_init: shm_zone == NULL");
		return NGX_ERROR;
	}
	shm_zone->init = ngx_http_drop_request_init_zone;

    	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    	h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    	if (h == NULL) 
	{
        	return NGX_ERROR;
    	}

    	*h = ngx_http_drop_request_handler;
	srand((unsigned)time(NULL));

    	return NGX_OK;
}



static ngx_int_t
ngx_http_drop_request_init_zone(ngx_shm_zone_t *shm_zone, void *data) {
	ngx_uint_t                       i;
	ngx_slab_pool_t                *shpool;

	shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

	ngx_http_drop_request_shm = ngx_slab_alloc(shpool,
							(sizeof (ngx_http_drop_request_status_shm_t)) *
							ngx_http_drop_request_arr->nelts);
	if (ngx_http_drop_request_shm == NULL)
	{
		return NGX_ERROR;
	}
	for (i=0; i<ngx_http_drop_request_arr->nelts; i++)
	{
		ngx_http_drop_request_shm[i].accepted = 0;
		ngx_http_drop_request_shm[i].refused = 0;
	}
	shm_zone->data = ngx_http_drop_request_shm;

	return NGX_OK;
}

static ngx_int_t ngx_http_drop_request_probability(ngx_uint_t per)
{
	ngx_uint_t num;

	if(0 == per)
	{
		return NGX_ERROR;
	}
	num = rand()%100;
	if(num <= per)
	{
		return NGX_OK;
	}
	return NGX_ERROR;
}

static ngx_int_t ngx_http_drop_request_isnum(ngx_str_t *name)
{
	if(name->len < 2 || name->len > 4)
	{
		return 0;
	}
	if(name->len == 2)
	{
		if(name->data[1] != '%' || name->data[0] < '0' || name->data[0] > '9')
		{
			return 0;
		}
	}
	else if(name->len == 3)
	{
		if(name->data[2] != '%' || name->data[0] < '0' || name->data[0] > '9'
			|| name->data[1] < '0' || name->data[1] > '9')
		{
			return 0;
		}
	}
	else if(name->len == 4)
	{
		if(name->data[3] != '%' || name->data[0] != '1' 
			|| name->data[1] != '0' || name->data[2] != '0')
		{
			return 0;
		}
	}
	return 1;
}


static ngx_int_t ngx_http_drop_request_procinit(ngx_cycle_t *cycle) {
	ngx_uint_t i;

	if (ngx_http_drop_request_arr->nelts == 0)
	{
		return NGX_OK;
	}

	for (i=0; i<ngx_http_drop_request_arr->nelts; i++)
	{
		ngx_http_drop_request_status[i].shm = &ngx_http_drop_request_shm[i];
	}
	return NGX_OK;
}

static char *
ngx_http_drop_request_show(ngx_conf_t *cf,ngx_command_t *cmd,void *conf)
{
	ngx_http_core_loc_conf_t *clcf;
	clcf = ngx_http_conf_get_module_loc_conf(cf,ngx_http_core_module);
	clcf->handler = ngx_http_drop_request_show_handler;

	return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_drop_request_show_handler(ngx_http_request_t *r)
{
	ngx_int_t rc;
	ngx_chain_t out;
	size_t size;
	ngx_buf_t *b;
	ngx_http_drop_request_status_t *stat;
	ngx_http_drop_request_status_shm_t *shm;
	ngx_uint_t	i;
	u_char	*output = NULL;
	u_char	*output_var = NULL;
	u_char	*output_file = NULL;
	u_char	*output_file_var = NULL;

	modify_flag = 0;
	index_flag = 0;
	per_flag = -1;
	out_html = 0;
	if(!(r->method & (NGX_HTTP_HEAD | NGX_HTTP_GET )))
	{
		return NGX_HTTP_NOT_ALLOWED;
	}

	rc = ngx_http_discard_request_body(r);
	if(rc != NGX_OK)
	{
		return rc;
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

	if(NGX_HTTP_NOT_FOUND == ngx_http_drop_request_argscheck(r))
	{
		return NGX_HTTP_NOT_FOUND;
	}

	if(modify_flag)
	{
		ngx_http_drop_request_modify(r);
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
	size = 5000*ngx_http_drop_request_arr->nelts;

	b = ngx_create_temp_buf(r->pool,size);

	if(NULL == b)
	{
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	out.buf = b;
	out.next = NULL;

	if(out_html)
	{
		b->last = ngx_sprintf(b->last,HTML_HEAD);
		output = OUTPUT_HTML;
		output_var = OUTPUT_VAR_HTML;
		output_file = OUTPUT_FILE_HTML;
		output_file_var = OUTPUT_FILE_VAR_HTML;
	}
	else
	{
		output = OUTPUT;
		output_var = OUTPUT_VAR;
		output_file = OUTPUT_FILE;
		output_file_var = OUTPUT_FILE_VAR;
	}
	
	b->last = ngx_sprintf(b->last,
				        output);
	for (i=0; i<ngx_http_drop_request_arr->nelts; i++) {
      	stat = &ngx_http_drop_request_status[i];
      	shm  = stat->shm;

      	b->last = ngx_sprintf(b->last,
        output_var, stat->index, stat->per,stat->location.len,stat->location.data,
                     shm->accepted, shm->refused);
   	 }	

	if(out_html)
	{
		b->last = ngx_sprintf(b->last,
						"</table>\n");
	}
	

	b->last = ngx_sprintf(b->last,
				        output_file);

	
	for (i=0; i<ngx_http_drop_request_arr->nelts; i++) {
      	stat = &ngx_http_drop_request_status[i];
      	shm  = stat->shm;

      	b->last = ngx_sprintf(b->last,
        output_file_var, stat->index,stat->file.len,stat->file.data);
   	 }	

	if(out_html)
	{
		b->last = ngx_sprintf(b->last,
						"</table>\n"
						"</body>\n"
						"</html>\n");
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


static ngx_int_t ngx_pow(ngx_int_t base,ngx_int_t exp)
{
	ngx_int_t	i;
	ngx_int_t sum = 1;
	for(i = 0 ; i < exp ;i++)
	{
		sum *= base;
	}
	return sum;
}
static ngx_int_t ngx_http_drop_request_argscheck(ngx_http_request_t *r)
{
	ngx_str_t	value;
	ngx_str_t	tmp;
	ngx_uint_t	i;
	ngx_uint_t	off;

	if(r->args.len)
	{
		if (ngx_http_arg(r, (u_char *) "html", 4, &value) == NGX_OK) 
		{
			if(!ngx_strncmp("true",value.data,ngx_strlen("true")))
			{
				out_html = 1 ;		
			}
		}
		if (ngx_http_arg(r, (u_char *) "action", 6, &value) == NGX_OK) 
		{
			if(!ngx_strncmp("modify",value.data,ngx_strlen("modify")))
			{
				modify_flag = 1 ;	
			}
			if (ngx_http_arg(r, (u_char *) "index", 5, &value) == NGX_OK) 
			{
				tmp = value;
				if((tmp.data = ngx_strchr(value.data,'&')) != NULL)
				{
					off = tmp.data - value.data;
					for(i = 0; i < off ;i ++)
					{
						if(value.data[i] < '0' || value.data[i]> '9' )
						{
							return NGX_HTTP_NOT_FOUND;
						}
						index_flag += (value.data[i] - '0') * ngx_pow(10,off-i-1);
					}
				}
				else
				{
					return NGX_HTTP_NOT_FOUND;
				}
				if (ngx_http_arg(r, (u_char *) "per", 3, &value) == NGX_OK) 
				{
					tmp = value;
					if((tmp.data = ngx_strchr(value.data,'%')) != NULL)
					{
						off = tmp.data - value.data;
						if(1 == off)
						{
							if(value.data[0] < '0' || value.data[0]> '9' )
							{
								return NGX_HTTP_NOT_FOUND;
							}
							per_flag =  (value.data[0] - '0');
						}
						else if(2 == off)
						{
							if(value.data[0] < '0' || value.data[0]> '9' 
								|| value.data[1] < '0' || value.data[1]> '9')
							{
								return NGX_HTTP_NOT_FOUND;
							}
							per_flag =  (value.data[0] - '0') * 10 + (value.data[1] - '0');
						}
						else if(3 == off)
						{
							if(value.data[0] == '1' && value.data[1] ==  '0' 
								&& value.data[2] == '0')
							{
								per_flag = 100;
							}
							else
							{
								return NGX_HTTP_NOT_FOUND;
							}
						}
						else
						{
							return NGX_HTTP_NOT_FOUND;
						}
					}
					else
					{
						return NGX_HTTP_NOT_FOUND;
					}
				}
			}
		}
		
		

		if(0 == (index_flag || modify_flag || out_html) && per_flag == -1)
		{
			return NGX_HTTP_NOT_FOUND;
		}
		
	}
	return NGX_OK;
}

static void	ngx_http_drop_request_modify(ngx_http_request_t *r)
{
	ngx_uint_t	i;
	ngx_http_drop_request_status_t *stat;
	ngx_http_drop_request_loc_shm_map_t	*maps;
	
	for(i = 0; i < ngx_http_drop_request_arr->nelts; i++)
	{
		stat = &ngx_http_drop_request_status[i];
		if(i == index_flag)
		{
			stat->loc_conf->per = (ngx_uint_t)per_flag;
			stat->per = per_flag;
			break;
		}
	}
	for (i=0; i<ngx_http_drop_request_loc_shm_map_arr->nelts; i++)
	{
		maps =  &ngx_http_drop_request_loc_shm_map[i];
		if(maps->index == index_flag)
		{
			maps->loc_conf->per= per_flag;
		}
	}
}


