/*
 * nginx upstream module, support cookie insert method.
 * author:	jianyi.weng
 * modified:	2011-03-16
 * version:	0.1.0
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define ngx_bitvector_index(index) index / (8 * sizeof(uintptr_t))
#define ngx_bitvector_bit(index) (uintptr_t) 1 << index % (8 * sizeof(uintptr_t))

typedef struct {
	void							*next;
	time_t                          time;
	ngx_uint_t						count;
	ngx_queue_t						queue;
}ngx_http_upstream_ci_queue_node_t;


typedef struct {
	struct sockaddr                *sockaddr;
	socklen_t                       socklen;
	ngx_str_t                       name;


	ngx_int_t						current_weight;
	ngx_int_t						weight;
	
	ngx_uint_t						fails;

	time_t							wakeup;
	time_t							freeze_time;

	ngx_uint_t						max_fails;
	time_t							fail_timeout;

#if (NGX_UPSTREAM_CHECK_MODULE)
    ngx_uint_t                      check_index;
	ngx_flag_t						lastdown;
#endif

	ngx_uint_t						down;		   /* unsigned	down:1; */
	ngx_uint_t						queue_max_lenth;
	ngx_uint_t						queue_curr_count;
	ngx_queue_t                   	queue;
	ngx_uint_t							queue_node_n;
	ngx_uint_t							free_queue_nodes_n;
	ngx_http_upstream_ci_queue_node_t   *queue_nodes;
	ngx_http_upstream_ci_queue_node_t   *free_queue_nodes;
} ngx_http_upstream_ci_peer_t;


typedef struct ngx_http_upstream_ci_peers_s ngx_http_upstream_ci_peers_t;


struct ngx_http_upstream_ci_peers_s{
	ngx_uint_t						number;
	ngx_uint_t						freeze_cnt;
	ngx_uint_t						last;
	ngx_uint_t						*hash_array;
	ngx_hash_t						*index;
	ngx_flag_t						backup;
#if (NGX_UPSTREAM_CHECK_MODULE)
	ngx_flag_t						all_down;
#endif
	ngx_http_upstream_ci_peers_t 	*next;
	ngx_http_upstream_ci_peer_t     peer[0];
};


typedef struct {
	ngx_http_upstream_ci_peers_t      *peers;
	ngx_str_t							secret;
	ngx_uint_t                   		curr;
	ngx_uint_t                   		tries;
	ngx_flag_t							freeze;
	ngx_flag_t							withcookie;
	uintptr_t                      		*tried;
    uintptr_t                       	data;
} ngx_http_upstream_ci_peer_data_t;

typedef struct {
	time_t                            expires;
	ngx_flag_t							freeze;
	ngx_flag_t							srand;
        ngx_uint_t                 cookie_insert_hash_max_size;
        ngx_uint_t                 cookie_insert_hash_bucket_size;
} ngx_http_upstream_ci_conf_t;


static ngx_int_t 
ngx_http_upstream_ci_create_queuenode(ngx_conf_t *cf,ngx_http_upstream_ci_peer_t *peer);

ngx_http_upstream_ci_queue_node_t *
ngx_http_upstream_ci_get_queuenode(ngx_http_upstream_ci_peer_t *peer);
static void
ngx_http_upstream_ci_free_queuenode(ngx_http_upstream_ci_queue_node_t *ucqn,ngx_http_upstream_ci_peer_t *peer);
static void
ngx_http_upstream_ci_clean_queue(ngx_http_upstream_ci_peer_t *peer);

static ngx_int_t ngx_http_upstream_ci_cmp_servers(const void *one,
    const void *two);
static ngx_int_t ngx_http_upstream_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_upstream_server_variable(ngx_http_request_t *r, 
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upstream_secret_variable(ngx_http_request_t *r, 
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upstream_expires_variable(ngx_http_request_t *r, 
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_uint_t
ngx_http_upstream_ci_get_peerbyweight(ngx_http_upstream_ci_peers_t *peers);
static ngx_int_t ngx_http_upstream_ci_init_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_ci_get_peer(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_upstream_ci_free_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);

static char *ngx_http_upstream_ci(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_upstream_ci_again(ngx_conf_t *cf, ngx_command_t *cmd, 
    void *conf);

static ngx_int_t ngx_http_upstream_ci_init(ngx_conf_t *cf, 
    ngx_http_upstream_srv_conf_t *us);
//static ngx_uint_t ngx_http_upstream_hash_crc32(u_char *keydata, size_t keylen);

static void *ngx_http_upstream_ci_create_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_ci_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t    ngx_http_upstream_ci_srandom(ngx_cycle_t *cycle);



static ngx_command_t  ngx_http_upstream_ci_commands[] = {
	{ ngx_string("cookie_insert"),
	  NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
	  ngx_http_upstream_ci,
	  0,
	  0,
	  NULL},

	{ ngx_string("cookie_expires"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_sec_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_upstream_ci_conf_t, expires),
	  NULL},

	{ ngx_string("cookie_again"),
	  NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
	  ngx_http_upstream_ci_again,
	  0,
	  0,
	  NULL },

	{ ngx_string("cookie_freeze"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
	  ngx_conf_set_flag_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_upstream_ci_conf_t, freeze),
	  NULL },
	  
	{ ngx_string("cookie_srand"),
	  NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
	  ngx_conf_set_flag_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_upstream_ci_conf_t, srand),
	  NULL }, 

	{ ngx_string("cookie_insert_hash_max_size"),
          NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
          ngx_conf_set_num_slot,
          NGX_HTTP_LOC_CONF_OFFSET,
          offsetof(ngx_http_upstream_ci_conf_t,cookie_insert_hash_max_size),
          NULL },

        { ngx_string("cookie_insert_hash_bucket_size"),
          NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
          ngx_conf_set_num_slot,
          NGX_HTTP_LOC_CONF_OFFSET,
          offsetof(ngx_http_upstream_ci_conf_t,cookie_insert_hash_bucket_size),
          NULL },
 
	ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_ci_module_ctx = {
	ngx_http_upstream_add_variables,       /* preconfiguration */
	NULL,                                  /* postconfiguration */

	NULL,                                  /* create main configuration */
	NULL,                                  /* init main configuration */

	NULL,                                  /* create server configuration */
	NULL,                                  /* merge server configuration */

	ngx_http_upstream_ci_create_conf,      /* create location configuration */
	ngx_http_upstream_ci_merge_conf        /* merge location configuration */
};

ngx_module_t  ngx_http_upstream_ci_module = {
	NGX_MODULE_V1,
	&ngx_http_upstream_ci_module_ctx,    /* module context */
	ngx_http_upstream_ci_commands,       /* module directives */
	NGX_HTTP_MODULE,                       /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	ngx_http_upstream_ci_srandom,          /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,                                  /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};

static ngx_http_variable_t ngx_http_upstream_ci_vars[] = {
	{ ngx_string("ci_server"), NULL, 
          ngx_http_upstream_server_variable, 0, 
	  NGX_HTTP_VAR_NOHASH|NGX_HTTP_VAR_NOCACHEABLE, 0 },
	{ ngx_string("ci_secret"), NULL, 
          ngx_http_upstream_secret_variable, 0, 
	  NGX_HTTP_VAR_NOHASH|NGX_HTTP_VAR_NOCACHEABLE, 0 },

	{ ngx_string("ci_expires"), NULL, 
          ngx_http_upstream_expires_variable, 0, 
	  NGX_HTTP_VAR_NOHASH|NGX_HTTP_VAR_NOCACHEABLE, 0 }

};

static ngx_int_t 
ngx_http_upstream_ci_create_queuenode(ngx_conf_t *cf,ngx_http_upstream_ci_peer_t *peer)
{
	ngx_uint_t							i;
	ngx_http_upstream_ci_queue_node_t 	*ucqn,*next;

	peer->queue_nodes =
	    ngx_pcalloc(cf->pool,sizeof(ngx_http_upstream_ci_queue_node_t) * peer->queue_node_n);
	if (peer->queue_nodes == NULL) {
	    return NGX_ERROR;
	}
	ucqn = peer->queue_nodes;
	i = peer->queue_node_n;
	next = NULL;
	do {
	    i--;
	    ucqn[i].next = next;
		ucqn[i].count = 0;
		ucqn[i].time = 0;
	    next = &ucqn[i];
	} while (i);

	peer->free_queue_nodes = next;
	peer->free_queue_nodes_n = peer->queue_node_n;
	return NGX_OK;
}

ngx_http_upstream_ci_queue_node_t *
ngx_http_upstream_ci_get_queuenode(ngx_http_upstream_ci_peer_t *peer)
{
	ngx_http_upstream_ci_queue_node_t 	*ucqn;
	ucqn = peer->free_queue_nodes;
	if(ucqn == NULL) {
		return NULL;
	}
	peer->free_queue_nodes = ucqn->next;
	peer->free_queue_nodes_n--;
	return ucqn;
}

static void
ngx_http_upstream_ci_free_queuenode(ngx_http_upstream_ci_queue_node_t *ucqn,ngx_http_upstream_ci_peer_t *peer)
{
	peer->queue_curr_count -= ucqn->count;
	ucqn->next = peer->free_queue_nodes;
	peer->free_queue_nodes = ucqn;
	peer->free_queue_nodes_n++;
}

static void
ngx_http_upstream_ci_clean_queue(ngx_http_upstream_ci_peer_t *peer)
{
	ngx_queue_t             			*q;
	ngx_http_upstream_ci_queue_node_t	*ucqn;
	
	while(!ngx_queue_empty(&peer->queue)) {
		q = ngx_queue_last(&peer->queue);
		ngx_queue_remove(q);
		ucqn = ngx_queue_data(q, ngx_http_upstream_ci_queue_node_t, queue);
		ngx_http_upstream_ci_free_queuenode(ucqn,peer);
	}
}

static ngx_int_t
ngx_http_upstream_ci_cmp_servers(const void *one, const void *two)
{
	ngx_http_upstream_ci_peer_t  *first, *second;

	first = (ngx_http_upstream_ci_peer_t *) one;
	second = (ngx_http_upstream_ci_peer_t *) two;

	return (first->weight < second->weight);
}


static ngx_int_t
ngx_http_upstream_add_variables(ngx_conf_t *cf)
{
	ngx_http_variable_t *var, *v;

	for (v = ngx_http_upstream_ci_vars; v->name.len; v++) {
		var = ngx_http_add_variable(cf, &v->name, v->flags);
		if (var == NULL) {
			return NGX_ERROR;
		}

		var->get_handler = v->get_handler;
		var->data = v->data;
	}

	return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_server_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	if ((r->upstream == NULL) || (r->upstream->peer.name == NULL)) {
	    v->not_found = 1;
	    return NGX_OK;
	}

	v->data = r->upstream->peer.name->data;
	v->len = r->upstream->peer.name->len;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
	               "upstream_ci: set $ci_server \"%V\"", r->upstream->peer.name);

	return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_secret_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	if ((r->upstream == NULL) || (r->upstream->peer.name == NULL)) {
	    v->not_found = 1;
	    return NGX_OK;
	}

	v->data = ngx_pnalloc(r->pool, r->upstream->peer.name->len * 4);
	v->len = r->upstream->peer.name->len * 4;

	ngx_encode_base64((ngx_str_t *)v, r->upstream->peer.name);

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
	               "upstream_ci: set $ci_secret \"%V\"", v);

	return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_expires_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
	size_t 							len;
	time_t 							t;
	ngx_http_upstream_ci_conf_t		*uccf;
	
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;
	len = sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1;


	uccf = (ngx_http_upstream_ci_conf_t *) ngx_http_get_module_loc_conf(r, ngx_http_upstream_ci_module);

	// NGX_HTTP_EXPIRES_MAX
	if ((uccf->expires == 0) || (uccf->expires == NGX_CONF_UNSET)) {
		v->data = (u_char *) "Thu, 31 Dec 2037 23:55:55 GMT";
		    v->len = len;

		return NGX_OK; 
	}

	t = ngx_time() + uccf->expires;

	v->data = ngx_pnalloc(r->pool, len);
	if (v->data == NULL) {
		return NGX_ERROR;
	}
	v->len = len;

	ngx_http_time(v->data, t);

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
	               "upstream_ci: set $spanner_expires \"%V\"", &v);

	return NGX_OK;
}


static ngx_int_t ngx_http_upstream_ci_srandom(ngx_cycle_t *cycle)
{
	srandom(ngx_pid);	
	return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_ci_init(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
	ngx_int_t 						*h;
	ngx_uint_t                       i, j, n,k;
	ngx_http_upstream_server_t      *server;
	ngx_http_upstream_ci_peers_t	*peers,*backup;
	ngx_http_upstream_ci_conf_t		*uccf;

	us->peer.init = ngx_http_upstream_ci_init_peer;

	if (!us->servers) {

	    return NGX_ERROR;
	}

	server = us->servers->elts;

	for (n = 0, i = 0; i < us->servers->nelts; i++) {
		if (server[i].backup) {
		    continue;
		}
		n += server[i].naddrs;
	}

	peers = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_ci_peers_t)
	        + sizeof(ngx_http_upstream_ci_peer_t) * n);

	if (peers == NULL) {
	    return NGX_ERROR;
	}

	uccf = ngx_http_conf_get_module_loc_conf(cf,ngx_http_upstream_ci_module);
	if(uccf->srand == NGX_CONF_UNSET) {
		uccf->srand = 0;
	}
	if(uccf->srand){
		h = ngx_pcalloc(cf->pool,sizeof(ngx_int_t) * n);
		if (h == NULL) {
	    	return NGX_ERROR;
		}
	}

	peers->hash_array = ngx_pcalloc(cf->pool,sizeof(ngx_uint_t) * (n + 1));
	if (peers->hash_array == NULL) {
	    	return NGX_ERROR;
	}

	if (uccf->cookie_insert_hash_max_size == NGX_CONF_UNSET_UINT) {
        	uccf->cookie_insert_hash_max_size = 1024;
    }

	if (uccf->cookie_insert_hash_bucket_size == NGX_CONF_UNSET_UINT) {
                uccf->cookie_insert_hash_bucket_size = 64;
    }	

	peers->number = n;
	peers->freeze_cnt= 0;
	peers->last = 0;
	peers->next = NULL;
	n = 0;
	k = 0;

	ngx_hash_init_t	 hash_init;
	ngx_array_t		*elems;
	ngx_hash_key_t	*arr_node;

	peers->index = (ngx_hash_t *) ngx_pcalloc(cf->pool, sizeof(ngx_hash_t));

	hash_init.hash = peers->index;
	hash_init.key = ngx_hash_key_lc;
	hash_init.max_size = uccf->cookie_insert_hash_max_size;
	hash_init.bucket_size = ngx_align(uccf->cookie_insert_hash_bucket_size, ngx_cacheline_size);
	hash_init.name = "upstream_in_ci";
	hash_init.pool = cf->pool;
	hash_init.temp_pool = NULL;

	elems = ngx_array_create(cf->pool, peers->number*6, sizeof(ngx_hash_key_t));
    
	/* one hostname can have multiple IP addresses in DNS */
	for (n = 0, i = 0; i < us->servers->nelts; i++) {
	    for (j = 0; j < server[i].naddrs; j++) {
			if (server[i].backup) {
				continue;
			}
			if(uccf->srand) {
				 while(1) {
					k = ngx_random() % us->servers->nelts;
					if(!h[k]) {
						break;
					}
				 }
				 h[k] = 1;
			}
			else {
				k = n;
			}
			peers->peer[k].sockaddr = server[i].addrs[j].sockaddr;
			peers->peer[k].socklen = server[i].addrs[j].socklen;
			peers->peer[k].name = server[i].addrs[j].name;
			peers->peer[k].max_fails = server[i].max_fails;
			peers->peer[k].fail_timeout = server[i].fail_timeout;
			peers->peer[k].freeze_time = server[i].freeze_time;
			peers->peer[k].down = server[i].down;
			peers->peer[k].weight = server[i].down ? 0 : server[i].weight;
			peers->peer[k].current_weight = peers->peer[k].weight;
			peers->peer[k].fails= 0;
			peers->peer[k].wakeup = 0;
			peers->peer[k].queue_curr_count = 0;
			peers->peer[k].queue_max_lenth =  peers->peer[k].fail_timeout + 1;
			peers->peer[k].queue_node_n = peers->peer[k].queue_max_lenth;
			if(ngx_http_upstream_ci_create_queuenode(cf,&peers->peer[k]) == NGX_ERROR) {
				ngx_log_error(NGX_LOG_ERR, cf->log, 0, 
							"upstream_ci:create_queuenode failed");
				return NGX_ERROR;
			}

#if (NGX_UPSTREAM_CHECK_MODULE)
			peers->peer[k].lastdown = 0;
			if (!server[i].down) {
				peers->peer[k].check_index = 
				ngx_http_check_add_peer(cf, us, &server[i].addrs[j]);
			}
			else {
				peers->peer[k].check_index = (ngx_uint_t) NGX_ERROR;
			}
#endif
			
			n++;
	    }
	}

	us->peer.data = peers;

	ngx_sort(&peers->peer[0], (size_t) n,
	             sizeof(ngx_http_upstream_ci_peer_t),
	             ngx_http_upstream_ci_cmp_servers);

	ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
		           "upstream_ci: upstream \"%V\" after srand the peers is:",
		           	&us->host);

	for (i = 0; i < n; i++) {
		ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
		           "\"%V\" weight:%d",
		           	&peers->peer[i].name,peers->peer[i].weight);
	}
	
	for (i = 0; i < n; i++) {
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, cf->log, 0,
		           "upstream_ci: after sort peers name:\"%V\" weight:%d",
		           	&peers->peer[i].name,peers->peer[i].weight);
		ngx_queue_init(&peers->peer[i].queue);
		arr_node = (ngx_hash_key_t *)ngx_array_push(elems);
		arr_node->key = peers->peer[i].name;
		arr_node->key_hash = ngx_hash_key_lc(arr_node->key.data, arr_node->key.len);
		arr_node->value = (void *)(i+1);
	}

	if (ngx_hash_init(&hash_init, elems->elts, elems->nelts) != NGX_OK) {
		return NGX_ERROR;
	}


	/* backup servers */

	n = 0;

	for (i = 0; i < us->servers->nelts; i++) {
	    if (!server[i].backup) {
	        continue;
	    }

	    n += server[i].naddrs;
	}

	if (n == 0) {
	    return NGX_OK;
	}

	backup = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_ci_peers_t)
	                      + sizeof(ngx_http_upstream_ci_peer_t) * n);
	if (backup == NULL) {
	    return NGX_ERROR;
	}

	backup->number = n;
	backup->freeze_cnt = 0;
	backup->last = 0;
	backup->next = NULL;
	n = 0;

	ngx_hash_init_t  hash_init_backup;
	ngx_array_t 	*elems_backup;
	ngx_hash_key_t	*arr_node_backup;

	backup->index = (ngx_hash_t *) ngx_pcalloc(cf->pool, sizeof(ngx_hash_t));

	hash_init_backup.hash = backup->index;
	hash_init_backup.key = ngx_hash_key_lc;
	hash_init_backup.max_size = uccf->cookie_insert_hash_max_size;
        hash_init_backup.bucket_size = ngx_align(uccf->cookie_insert_hash_bucket_size, ngx_cacheline_size);
	hash_init_backup.name = "upstream_in_ci_backup";
	hash_init_backup.pool = cf->pool;
	hash_init_backup.temp_pool = NULL;

	elems_backup = ngx_array_create(cf->pool, backup->number*6, sizeof(ngx_hash_key_t));

	for (i = 0; i < us->servers->nelts; i++) {
	    for (j = 0; j < server[i].naddrs; j++) {
	        if (!server[i].backup) {
	            continue;
	        }

			backup->peer[n].sockaddr = server[i].addrs[j].sockaddr;
			backup->peer[n].socklen = server[i].addrs[j].socklen;
			backup->peer[n].name = server[i].addrs[j].name;
			backup->peer[n].weight = server[i].weight;
			backup->peer[n].current_weight = server[i].weight;
			backup->peer[n].max_fails = server[i].max_fails;
			backup->peer[n].fail_timeout = server[i].fail_timeout;
			backup->peer[n].freeze_time = server[i].freeze_time;
			backup->peer[n].down = server[i].down;
			backup->peer[n].fails = 0;
			backup->peer[n].wakeup = 0;
			backup->peer[n].queue_curr_count = 0;
			backup->peer[n].queue_max_lenth =  backup->peer[n].fail_timeout + 1;
			backup->peer[n].queue_node_n = backup->peer[n].queue_max_lenth;
			if(ngx_http_upstream_ci_create_queuenode(cf,&backup->peer[n]) == NGX_ERROR) {
				ngx_log_error(NGX_LOG_ERR, cf->log, 0, 
							"upstream_ci:create_queuenode failed");
				return NGX_ERROR;
			}

#if (NGX_UPSTREAM_CHECK_MODULE)
			if (!server[i].down) {
				backup->peer[n].check_index = 
				ngx_http_check_add_peer(cf, us, &server[i].addrs[j]);
			}
			else {
				backup->peer[n].check_index = (ngx_uint_t) NGX_ERROR;
			}
#endif
			n++;
	    }
	}

	peers->next = backup;

	ngx_sort(&backup->peer[0], (size_t) n,
	         sizeof(ngx_http_upstream_ci_peer_t),
	         ngx_http_upstream_ci_cmp_servers);


	for (i = 0; i < n; i++) {
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, cf->log, 0,
	           "upstream_ci: after sort backup name:\"%V\" weight:%d",
	           	&backup->peer[i].name,backup->peer[i].weight);
		ngx_queue_init(&backup->peer[i].queue);
		arr_node_backup = (ngx_hash_key_t *)ngx_array_push(elems_backup);
		arr_node_backup->key = backup->peer[i].name;
		arr_node_backup->key_hash = ngx_hash_key_lc(arr_node_backup->key.data, arr_node_backup->key.len);
		arr_node_backup->value = (void *)(i+1);
	}

	if (ngx_hash_init(&hash_init_backup, elems_backup->elts, elems_backup->nelts) != NGX_OK) {
		return NGX_ERROR;
	}

	return NGX_OK;
}

static ngx_uint_t
ngx_upstream_ci_get_randompeer(ngx_http_upstream_ci_peers_t  *peers,ngx_uint_t end)
{
	ngx_uint_t    ret;

	if (end == 1) {
		return peers->hash_array[0];
	}
	
	ret = ngx_random() % end;
	
	return peers->hash_array[ret];
}


static ngx_uint_t
ngx_http_upstream_ci_get_peerbyweight(ngx_http_upstream_ci_peers_t *peers)
{
	time_t 						now;
	ngx_uint_t					i, n;
	ngx_uint_t					end,weight;
#if (NGX_UPSTREAM_CHECK_MODULE)
	ngx_uint_t					ngx_peer_down_cnt;
	ngx_uint_t					ngx_loop_cnt;
#endif
	ngx_http_upstream_ci_peer_t  *peer;

	peer = &peers->peer[0];
	now = ngx_time();
#if (NGX_UPSTREAM_CHECK_MODULE)
	ngx_loop_cnt = 0;
#endif

	for ( ;; ) {
#if (NGX_UPSTREAM_CHECK_MODULE)
		ngx_peer_down_cnt = 0;
#endif
		end = 0;
		for (i = 0; i < peers->number; i++) {


			if(peer[i].wakeup != 0 && peer[i].wakeup <= now) {
				peer[i].fails = 0;
				peer[i].wakeup = 0;
				peer[i].current_weight = 0;
				ngx_http_upstream_ci_clean_queue(&peer[i]);
				peers->freeze_cnt--;
			}
			
#if (NGX_UPSTREAM_CHECK_MODULE)
			if(!ngx_http_check_peer_down(peer[i].check_index)) {
				if(peer[i].lastdown) {
					peer[i].lastdown = 0;
					peer[i].current_weight = 0;
				}
			}
			else {
				peer[i].current_weight = 0;
				peer[i].lastdown = 1;
				continue;
			} 
#endif

			if (peer[i].current_weight <= 0 || peer[i].wakeup != 0) {
			    continue;
			}
				
			n = i;
			peers->hash_array[end++] = i;
			weight = peer[i].current_weight;

			while (i < peers->number - 1) {

				i++;

				if(peer[i].wakeup != 0 && peer[i].wakeup <= now) {
					peer[i].fails = 0;
					peer[i].wakeup = 0;
					peer[i].current_weight = 0;
					ngx_http_upstream_ci_clean_queue(&peer[i]);
					peers->freeze_cnt--;
				}


#if (NGX_UPSTREAM_CHECK_MODULE)
				if(!ngx_http_check_peer_down(peer[i].check_index)) {
					if(peer[i].lastdown) {
						peer[i].lastdown = 0;
						peer[i].current_weight = 0;
					}
				}
				else {
					peer[i].current_weight = 0;
					peer[i].lastdown = 1;
					continue;
				} 
#endif

				if (peer[i].current_weight <=  0 || peer[i].wakeup != 0) {
				    continue;
				}


				if (peer[n].current_weight * 1000 / peer[i].current_weight
				    > peer[n].weight * 1000 / peer[i].weight)
				{
					n = ngx_upstream_ci_get_randompeer(peers,end);
				    return n;
				}

			    n = i;
				if (weight != peer[i].current_weight) {
					end = 0;
					weight = peer[i].current_weight;
				}
				peers->hash_array[end++] = i;
				
			}

			/*if (peer[i].current_weight > 0) {
			    n = i;
				if (weight != peer[i].current_weight) {
					end = 0;
					weight = peer[i].current_weight;
				}
				peers->hash_array[end++] = i;
			}*/

			n = ngx_upstream_ci_get_randompeer(peers,end);
	        return n;
	    }

		for (i = 0; i < peers->number; i++) {

#if (NGX_UPSTREAM_CHECK_MODULE)
			if(ngx_http_check_peer_down(peer[i].check_index)) {
				ngx_peer_down_cnt++;
				continue;
			}
#endif

			if(peer[i].wakeup != 0) {
				continue;
			}

		    peer[i].current_weight = peer[i].weight;
		}
#if (NGX_UPSTREAM_CHECK_MODULE)
		if(ngx_peer_down_cnt == peers->number) {
			peers->all_down = 1;
			return 0;
		}
		if(ngx_loop_cnt >= 1) {
			peers->all_down = 1;
			return 0;
		}
		ngx_loop_cnt++;
#endif

	}
}


static ngx_int_t
ngx_http_upstream_ci_init_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
	ngx_str_t 							val;
	ngx_uint_t                         	n;
	ngx_uint_t 							*number;
	ngx_uint_t 							*last,peer_index;
	ngx_http_upstream_ci_conf_t			*uccf;
	ngx_http_upstream_ci_peer_data_t	*ucpd;

	if (ngx_http_script_run(r, &val, us->lengths, 0, us->values) == NULL) {
	    return NGX_ERROR;
	}

	ucpd = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_ci_peer_data_t)
	        + sizeof(uintptr_t) * 
	            ((ngx_http_upstream_ci_peers_t *)us->peer.data)->number / 
	                (8 * sizeof(uintptr_t)));

	if (ucpd == NULL) {
	    return NGX_ERROR;
	}

	r->upstream->peer.data = ucpd;
	uccf = ngx_http_get_module_loc_conf(r,ngx_http_upstream_ci_module);

	ucpd->peers = us->peer.data;
	ucpd->freeze = uccf->freeze;
	ucpd->peers->backup = 0;
#if (NGX_UPSTREAM_CHECK_MODULE)
	ucpd->peers->all_down = 0;
#endif

	if (ucpd->peers->number <= 8 * sizeof(uintptr_t)) {
        ucpd->tried = &ucpd->data;
        ucpd->data = 0;

    } else {
        n = (ucpd->peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        ucpd->tried = ngx_pcalloc(r->pool, n * sizeof(uintptr_t));
        if (ucpd->tried == NULL) {
            return NGX_ERROR;
        }
    }

	r->upstream->peer.free = ngx_http_upstream_ci_free_peer;
	r->upstream->peer.get = ngx_http_upstream_ci_get_peer;
	if(us->retries == 0) {
		r->upstream->peer.tries = ucpd->peers->number;
	}
	else {
		r->upstream->peer.tries = us->retries + 1;
	}

	ucpd->tries = r->upstream->peer.tries;

	if ((ucpd->secret.data = ngx_pcalloc(r->pool, 256)) == NULL) {
	    return NGX_ERROR;
	}

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
	               "upstream_ci:  val.len:%d", val.len);

	if (val.len == 0) {
		last = &((ngx_http_upstream_ci_peers_t *)us->peer.data)->last;
		number = &((ngx_http_upstream_ci_peers_t *)us->peer.data)->number;
		peer_index = ngx_http_upstream_ci_get_peerbyweight(ucpd->peers);
		*last = peer_index;
		ngx_memcpy(ucpd->secret.data, ucpd->peers->peer[*last].name.data, ucpd->peers->peer[*last].name.len);
		ucpd->secret.len = ucpd->peers->peer[*last].name.len;
		ucpd->withcookie = 0;

		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
						"upstream_ci:  the request has no cookies,will chose the last:%d peer \"%V\"", *last,&ucpd->secret);

		*last = (*last+1) % *number;
	} 
	else {
		ucpd->withcookie = 1;
		ngx_decode_base64(&ucpd->secret, &val);
	}
        
	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
	               "upstream_ci:  ucpd->secret \"%V\"(%d)", &ucpd->secret, ucpd->secret.len);

	return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_ci_get_peer(ngx_peer_connection_t *pc, void *data)
{
	time_t								now,last_time;
	ngx_int_t							peer_index,rc;
	uintptr_t							m;
	ngx_uint_t							*last,*number,n,i,k;
	ngx_queue_t							*q;
	ngx_http_upstream_ci_peer_t			*peer;
	ngx_http_upstream_ci_peers_t		*peers;
	ngx_http_upstream_ci_queue_node_t	*ucqn,*ucqn_t;
	ngx_http_upstream_ci_peer_data_t	*ucpd = data;


	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
	               "upstream_ci: get upstream request hash peer try %ui", pc->tries);

	now = ngx_time();
	number = &ucpd->peers->number;
	pc->cached = 0;
	pc->connection = NULL;
#if (NGX_UPSTREAM_CHECK_MODULE)
	if(ucpd->peers->all_down) {
		pc->tries = 0;
		goto failed;
	}
#endif
	i = ucpd->tries;
	for(;;)
	{

		k = ngx_hash_key_lc(ucpd->secret.data, ucpd->secret.len);
		peer_index = (ngx_uint_t) ngx_hash_find(ucpd->peers->index, k, ucpd->secret.data, ucpd->secret.len);

		peer_index -= 1;

		ngx_log_debug3(NGX_LOG_DEBUG_HTTP, pc->log, 0, 
			"upstream_ci: chose peer %ui key:\"%s\" key_hash:\"%ud\"", 
				peer_index, ucpd->secret.data, k);

		if ((peer_index < 0) || (peer_index >= (ngx_int_t)ucpd->peers->number)) {
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, 
							"upstream_ci: no match cookie");
			last = &ucpd->peers->last;
			peer_index = ngx_http_upstream_ci_get_peerbyweight(ucpd->peers);
#if (NGX_UPSTREAM_CHECK_MODULE)
			if(ucpd->peers->all_down) {
				pc->tries = 0;
				goto failed;
			}
#endif
			*last = peer_index;
			ucpd->withcookie = 0;
			*last = (*last + 1) % *number;
		}
		peer = &ucpd->peers->peer[peer_index];
		ucpd->curr = peer_index;
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0, 
						"upstream_ci:get peer  name:\"%V\" fails:%ui", 
						&peer->name,peer->fails);
		if(!ucpd->freeze) {
			break;
		}
		
		if(peer->wakeup != 0 && peer->wakeup <= now){
			peer->fails = 0;
			peer->wakeup = 0;
			peer->current_weight = 0;
			ngx_http_upstream_ci_clean_queue(peer);
			ucpd->peers->freeze_cnt--;
		}

		n = ucpd->curr / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << ucpd->curr % (8 * sizeof(uintptr_t));

		if (!(ucpd->tried[n] & m)) {
			if (!peer->down && !peer->wakeup) {

#if (NGX_UPSTREAM_CHECK_MODULE)
	        	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
	                       "get ci_upstream peer, check_index: %ui", peer->check_index);
	            if (!ngx_http_check_peer_down(peer->check_index)) {
					if(peer->lastdown) {
						peer->lastdown = 0;
						peer->current_weight = 0;
					}
#endif

					if (peer->max_fails == 0
					|| peer->fails < peer->max_fails)
					{
						ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, 
								"upstream_ci:yes,the peer  name:\"%V\" fails < maxsfails", 
								&peer->name);
						break;
					}

					ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, 
								"upstream_ci:the peer  name:\"%V\" fails >= maxsfails", 
								&peer->name);
					last_time = 0;

					if (!ngx_queue_empty(&peer->queue)) {
						q = ngx_queue_head(&peer->queue);
						ucqn = ngx_queue_data(q, ngx_http_upstream_ci_queue_node_t, queue);
						last_time = ucqn->time;
						q = ngx_queue_last(&peer->queue);
						ucqn_t = ngx_queue_data(q, ngx_http_upstream_ci_queue_node_t, queue);
						ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0, 
								"upstream_ci:queue head tiime:%ld queue tail time:%ld", 
								ucqn->time,ucqn_t->time);
					}

					if (now - last_time > peer->fail_timeout) {
						ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, 
								"upstream_ci:yes,the peer  name:\"%V\" time > fail_timeout", 
								&peer->name);
						while(!ngx_queue_empty(&peer->queue)) {

							q = ngx_queue_head(&peer->queue);
							ucqn = ngx_queue_data(q, ngx_http_upstream_ci_queue_node_t, queue);
							if(now - ucqn->time <= peer->fail_timeout) {
								break;
							}
							ngx_queue_remove(q);
							ngx_http_upstream_ci_free_queuenode(ucqn,peer);
						}

						peer->fails = peer->queue_curr_count;
						ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, 
								"upstream_ci:the peer  fails:%ui", 
								peer->fails);
						break;
					}

					ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, 
								"upstream_ci:the peer  name:\"%V\" failstime <= fail_timeout", 
								&peer->name);
					//peer->current_weight = 0;

#if (NGX_UPSTREAM_CHECK_MODULE)
	           }
			   else {
					peer->lastdown = 1;
			   }
#endif
			}
			pc->tries--;
			ucpd->tried[n] |= m;
			peer->current_weight = 0;
			ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0, 
							"upstream_ci: get peer faild ,the peer  name:\"%V\" ,current left %d tries", 
							&peer->name,pc->tries);
		}
		if (pc->tries == 0) {
			goto failed;
		}

		if (i-- == 0) {
            ngx_log_error(NGX_LOG_ALERT, pc->log, 0,
                          "upstream ci stuck on %ui tries",
                          pc->tries);
            goto failed;
        }
		
		last = &ucpd->peers->last;
		peer = &ucpd->peers->peer[*last];
		ngx_memcpy(ucpd->secret.data, peer->name.data, peer->name.len);
		ucpd->secret.len = peer->name.len;
		ucpd->withcookie = 0;
		*last = (*last+1) % *number;

		//ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
		 //         "upstream_ci:  last:%d", *last);

		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, 
						"upstream_ci:next will chose the peer  name:\"%V\"", 
						&peer->name);
		
	}
	if(!ucpd->withcookie) {
		peer->current_weight--;
	}
	if(ucpd->freeze) {
		ucpd->tried[n] |= m;
	}
	pc->sockaddr = peer->sockaddr;
	pc->socklen = peer->socklen;
	pc->name = &peer->name;
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, 
						"upstream_ci:success chose the peer  name:\"%V\"", 
						&peer->name);
	return NGX_OK;

failed:

	peers = ucpd->peers;
	if (peers->next && !peers->backup) {

	    /* ngx_unlock_mutex(peers->mutex); */
	    ngx_log_error(NGX_LOG_ERR, pc->log, 0, "upstream_ci:backup servers");
		peers->backup = 1;
	    ucpd->peers = peers->next;
	    pc->tries = ucpd->peers->number;

	    rc = ngx_http_upstream_ci_get_peer(pc, ucpd);

		if (rc != NGX_BUSY) {
		    return rc;
		}

	    /* ngx_lock_mutex(peers->mutex); */
	}

	/* all peers failed, mark them as live for quick recovery */

	//for (i = 0; i < peers->number; i++) {
	//    peers->peer[i].fails = 0;
	//	peers->peer[i].wakeup = 0;
	//}

	/* ngx_unlock_mutex(peers->mutex); */

	//pc->name = peers->name;
	ngx_log_error(NGX_LOG_ERR, pc->log, 0, "upstream_ci:all peers failed");
	return NGX_BUSY;
}

/* retry implementation is PECL memcache compatible */
static void
ngx_http_upstream_ci_free_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
	time_t								now;
	ngx_uint_t							*last,curr,*number,i;
	ngx_queue_t							*q;
	ngx_http_upstream_ci_peer_t			*peer;
	ngx_http_upstream_ci_peers_t		*peers;
	ngx_http_upstream_ci_peer_data_t	*ucpd = data;
	ngx_http_upstream_ci_queue_node_t	*ucqn_t,*ucqn_h,*ucqn;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, 
	        "upstream_ci: free upstream hash peer try %ui", pc->tries-1);

	if (state == 0 && pc->tries == 0) {
        return;
    }

	if (state & (NGX_PEER_FAILED)
	        && pc->tries){
		pc->tries--;
		last = &ucpd->peers->last;
		number = &ucpd->peers->number;
		if(ucpd->freeze){
			now = ngx_time();
			curr = ucpd->curr;
			peer= &ucpd->peers->peer[curr];
			peer->fails++;
			
			ngx_log_error(NGX_LOG_ERR, pc->log, 0, 
							"upstream_ci:free the peer  name:\"%V\" fails:%ui",
							&peer->name,peer->fails);
			if (!ngx_queue_empty(&peer->queue)) {

				q = ngx_queue_last(&peer->queue);
				ucqn_t = ngx_queue_data(q, ngx_http_upstream_ci_queue_node_t, queue);
				q = ngx_queue_head(&peer->queue);
				ucqn_h = ngx_queue_data(q, ngx_http_upstream_ci_queue_node_t, queue);
				if(peer->fails >= peer->max_fails && (now - ucqn_h->time) <= peer->fail_timeout){
					ngx_log_error(NGX_LOG_ERR, pc->log, 0, 
								"upstream_ci:the peer  name:\"%V\" has been freeze,now is %d",
								&peer->name,now);
					if(peer->wakeup == 0) {
						ucpd->peers->freeze_cnt++;
					}
					peer->wakeup = now + peer->freeze_time;
					ngx_log_error(NGX_LOG_ERR, pc->log, 0, 
								"upstream_ci:will be wakeup at %d",
								peer->wakeup);
					peer->current_weight = 0;
				}
				else {
					if(now == ucqn_t->time) {
						ucqn_t->count++;
						peer->queue_curr_count++;
					}
					else {
						if(!peer->free_queue_nodes_n) {
							while(!ngx_queue_empty(&peer->queue)) {

								q = ngx_queue_head(&peer->queue);
								ucqn_h = ngx_queue_data(q, ngx_http_upstream_ci_queue_node_t, queue);
								if(now - ucqn_h->time <= peer->fail_timeout) {
									break;
								}
								ngx_queue_remove(q);
								ngx_http_upstream_ci_free_queuenode(ucqn_h,peer);
							}
						}
						ucqn = ngx_http_upstream_ci_get_queuenode(peer);
						if(ucqn == NULL) {
							ngx_log_error(NGX_LOG_ERR, pc->log, 0, 
								"upstream_ci:get queuenode failed");
							return;
						}
						ucqn->count = 1;
						ucqn->time = now;
						ngx_queue_insert_tail(&peer->queue,&ucqn->queue);
						peer->queue_curr_count++;
						peer->fails = peer->queue_curr_count;
						ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, 
							"upstream_ci:the peer  queue_curr_count:%ui", 
							peer->queue_curr_count);
					}
				}
			}
			else {
				if(peer->fails >= peer->max_fails){
					ngx_log_error(NGX_LOG_ERR, pc->log, 0, 
								"upstream_ci:the peer  name:\"%V\" has been freeze",
								&peer->name);
					if(peer->wakeup == 0) {
						ucpd->peers->freeze_cnt++;
					}
					peer->wakeup = now + peer->freeze_time;
				}
				else {
					ucqn = ngx_http_upstream_ci_get_queuenode(peer);
					if(ucqn == NULL) {
						ngx_log_error(NGX_LOG_ERR, pc->log, 0, 
							"upstream_ci:get queuenode failed");
						return;
					}
					ucqn->count = 1;
					ucqn->time = now;
					ngx_queue_insert_tail(&peer->queue,&ucqn->queue);
					peer->queue_curr_count++;
					ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, 
								"upstream_ci:the peer  queue_curr_count:%ui", 
								peer->queue_curr_count);
				}
			}
			if(ucpd->peers->freeze_cnt == ucpd->peers->number){
				/* all peers failed, mark them as live for quick recovery */

				for (i = 0; i < ucpd->peers->number; i++) {
				    ucpd->peers->peer[i].fails = 0;
					ucpd->peers->peer[i].wakeup = 0;
					ucpd->peers->peer[i].current_weight = ucpd->peers->peer[i].weight;
					ngx_http_upstream_ci_clean_queue( &ucpd->peers->peer[i]);
				}
				ucpd->peers->freeze_cnt = 0;
			}

			if(peer->current_weight < 0) {
				peer->current_weight = 0;
			}
		}
		
		//if (peer->max_fails) {
		//        peer->current_weight -= peer->weight / peer->max_fails;
		//}
		
		if(pc->tries){
			*last = ngx_http_upstream_ci_get_peerbyweight(ucpd->peers);
			ngx_memcpy(ucpd->secret.data, ucpd->peers->peer[*last].name.data, ucpd->peers->peer[*last].name.len);
			ucpd->secret.len = ucpd->peers->peer[*last].name.len;
			ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
	                   "upstream_ci:  next will chose the peer  name:\"%V\"", &ucpd->peers->peer[*last].name);
			ucpd->withcookie = 0;
			*last = (*last+1) % *number;
		}
		else {
			peers = ucpd->peers;

			if (peers->next && !peers->backup) {

			    /* ngx_unlock_mutex(peers->mutex); */
			    ngx_log_error(NGX_LOG_ERR, pc->log, 0, "upstream_ci:backup servers");
				peers->backup = 1;
			    ucpd->peers = peers->next;
			    pc->tries = ucpd->peers->number;

			    /* ngx_lock_mutex(peers->mutex); */
			}
		}
	}
	else {
		if(pc->tries) {
			pc->tries--;
		}
	}
}

static char *
ngx_http_upstream_ci(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_str_t                     *value;
	ngx_array_t                   *vars_lengths, *vars_values;
	ngx_http_script_compile_t      sc;
	ngx_http_upstream_srv_conf_t  *uscf;

	value = cf->args->elts;

	ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

	vars_lengths = NULL;
	vars_values = NULL;

	sc.cf = cf;
	sc.source = &value[1];
	sc.lengths = &vars_lengths;
	sc.values = &vars_values;
	sc.complete_lengths = 1;
	sc.complete_values = 1;

	if (ngx_http_script_compile(&sc) != NGX_OK) {
	    return NGX_CONF_ERROR;
	}

	uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

	uscf->peer.init_upstream = ngx_http_upstream_ci_init;

	uscf->flags = NGX_HTTP_UPSTREAM_CREATE
	              |NGX_HTTP_UPSTREAM_MAX_FAILS
	              |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
	              |NGX_HTTP_UPSTREAM_DOWN
	              |NGX_HTTP_UPSTREAM_BACKUP
	              |NGX_HTTP_UPSTREAM_WEIGHT;

	uscf->values = vars_values->elts;
	uscf->lengths = vars_lengths->elts;

	return NGX_CONF_OK;
}

static char *
ngx_http_upstream_ci_again(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_int_t n;
	ngx_str_t *value;
	ngx_http_upstream_srv_conf_t  *uscf;

	uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

	value = cf->args->elts;

	n = ngx_atoi(value[1].data, value[1].len);

	if (n == NGX_ERROR || n < 0) {
	    return "invalid number";
	}

	uscf->retries = n;

	return NGX_CONF_OK;
}


static void *
ngx_http_upstream_ci_create_conf(ngx_conf_t *cf)
{
	ngx_http_upstream_ci_conf_t  *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_ci_conf_t));
	if (conf == NULL) {
	    return NULL;
	}

	conf->expires = NGX_CONF_UNSET;
	conf->freeze = NGX_CONF_UNSET;
	conf->srand = NGX_CONF_UNSET;
        conf->cookie_insert_hash_max_size = NGX_CONF_UNSET;
        conf->cookie_insert_hash_bucket_size = NGX_CONF_UNSET;

	return conf;
}


static char *
ngx_http_upstream_ci_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_upstream_ci_conf_t *prev = parent;
	ngx_http_upstream_ci_conf_t *conf = child;

	ngx_conf_merge_sec_value(conf->expires, prev->expires, 0);
	ngx_conf_merge_value(conf->freeze, prev->freeze, 0);

	return NGX_CONF_OK;
}



