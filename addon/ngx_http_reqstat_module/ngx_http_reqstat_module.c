
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define REQSTAT_FIELD_CONN_TOTAL_OFFSET         offsetof(ngx_http_reqstat_item_t, conn_total)
#define REQSTAT_FIELD_CONN_ING_OFFSET           offsetof(ngx_http_reqstat_item_t, conn_count)
#define REQSTAT_FIELD_REQ_TOTAL_OFFSET          offsetof(ngx_http_reqstat_item_t, req_total)
#define REQSTAT_FIELD_REQ_ING_OFFSET            offsetof(ngx_http_reqstat_item_t, req_count)
#define REQSTAT_FIELD_BYTES_IN_OFFSET           offsetof(ngx_http_reqstat_item_t, bytes_in)
#define REQSTAT_FIELD_BYTES_OUT_OFFSET          offsetof(ngx_http_reqstat_item_t, bytes_out)
#define REQSTAT_FIELD_RT_MIN_OFFSET             offsetof(ngx_http_reqstat_item_t, rt_min)
#define REQSTAT_FIELD_RT_MAX_OFFSET             offsetof(ngx_http_reqstat_item_t, rt_max)
#define REQSTAT_FIELD_RT_AVR_OFFSET             offsetof(ngx_http_reqstat_item_t, rt_avr)
#define REQSTAT_FIELD_CONN_RATE_OFFSET          offsetof(ngx_http_reqstat_item_t, conn_rate_last)
#define REQSTAT_FIELD_REQ_RATE_OFFSET           offsetof(ngx_http_reqstat_item_t, req_rate_prev)

#define REQSTAT_FIELD_REQ_TOTAL(it)             (&(it)->req_total)
#define REQSTAT_FIELD_REQ_ING(it)               (&(it)->req_count)
#define REQSTAT_FIELD_CONN_TOTAL(it)            (&(it)->conn_total)
#define REQSTAT_FIELD_CONN_ING(it)              (&(it)->conn_count)
#define REQSTAT_FIELD_BYTES_IN(it)              (&(it)->bytes_in)
#define REQSTAT_FIELD_BYTES_OUT(it)             (&(it)->bytes_out)

/*rt*/
#define REQSTAT_FIELD_RT_MIN(it)                (&(it)->rt_min)
#define REQSTAT_FIELD_RT_MAX(it)                (&(it)->rt_max)
#define REQSTAT_FIELD_RT_AVR(it)                (&(it)->rt_avr)

/*conn rate*/
#define REQSTAT_FIELD_CONN_RATE_PREV(it)        (&(it)->conn_rate_last)
#define REQSTAT_FIELD_CONN_RATE(it)             (&(it)->conn_rate)

/*req rate*/
#define REQSTAT_FIELD_REQ_RATE_PREV(it)         (&(it)->req_rate_prev)
#define REQSTAT_FIELD_REQ_RATE(it)              (&(it)->req_rate)

#define SHM_HEAD(zone)                          ((ngx_http_reqstat_shm_head_t*) zone->shm.addr) 
#define SHM_LOCKER(zone)                        ((ngx_http_reqstat_shm_head_t*) zone->shm.addr) 
#define SHM_DATA(zone)                          ((ngx_http_reqstat_item_t*)(zone->shm.addr + \
                                                ngx_align(sizeof(ngx_http_reqstat_shm_head_t), 128)))
#define ZONE(it, offset)                         ((void*)((char*)it + offset))

#define KLEN                                    64

typedef struct ngx_http_reqstat_item_s {

    uint32_t                    hash;
    u_char                      key[KLEN];
    ngx_atomic_int_t            req_total;
    ngx_atomic_int_t            req_count;
    ngx_atomic_int_t            conn_total;
    ngx_atomic_int_t            conn_count;
    
    /*bytes*/
    ngx_atomic_int_t            bytes_in;
    ngx_atomic_int_t            bytes_out;
    
    /*rt*/
    ngx_uint_t                  rt_min;
    ngx_uint_t                  rt_max;
    ngx_uint_t                  rt_avr;
    
    /*conn rate*/
    time_t                      tm;
    ngx_uint_t                  conn_rate_last;
    ngx_uint_t                  conn_rate;
    
    /*req rate*/
    ngx_uint_t                  req_rate_prev;
    ngx_uint_t                  req_rate;

} ngx_http_reqstat_item_t;

typedef struct {
    ngx_uint_t                  workers;
    ngx_uint_t                  nsrv;
    ngx_shm_zone_t             *reqstat_zone;
    ngx_cycle_t                *cycle;
    void                       *data;
} ngx_http_reqstat_main_conf_t;

typedef struct {
    ngx_cycle_t                *cycle;
    void                       *data;
}ngx_http_reqstat_ctx_t;     

typedef struct {
    ngx_shmtx_sh_t              shmtx;
    ngx_shmtx_t                 mutex;
}ngx_http_reqstat_shm_head_t;

typedef struct field {
    ngx_str_t                   title;
    ngx_uint_t                  offset;
} ngx_http_reqstat_field_t;

static ngx_http_reqstat_field_t fields[] = {

    {ngx_string("conn_total"),  REQSTAT_FIELD_CONN_TOTAL_OFFSET  },
    {ngx_string("conn_count"),  REQSTAT_FIELD_CONN_ING_OFFSET    },
    {ngx_string("req_total"),   REQSTAT_FIELD_REQ_TOTAL_OFFSET   },
    {ngx_string("req_count"),   REQSTAT_FIELD_REQ_ING_OFFSET     },
    {ngx_string("bytes_in"),    REQSTAT_FIELD_BYTES_IN_OFFSET    },
    {ngx_string("bytes_out"),   REQSTAT_FIELD_BYTES_OUT_OFFSET   },
    {ngx_string("rt_min"),      REQSTAT_FIELD_RT_MIN_OFFSET      },
    {ngx_string("rt_max"),      REQSTAT_FIELD_RT_MAX_OFFSET      },
    {ngx_string("rt_avr"),      REQSTAT_FIELD_RT_AVR_OFFSET      },
    {ngx_string("conn_rate"),   REQSTAT_FIELD_CONN_RATE_OFFSET   },
    {ngx_string("req_rate"),    REQSTAT_FIELD_REQ_RATE_OFFSET    }

}; 

static ngx_str_t shm_name = ngx_string("reqstat_zone");

static ngx_int_t ngx_http_reqstat_init (ngx_conf_t *cf);

static void *ngx_http_reqstat_create_main_conf (ngx_conf_t *cf);

static char *ngx_http_reqstat_show (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t ngx_http_reqstat_commands[] = {
    {
        ngx_string("reqstat_show"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_http_reqstat_show,
        NGX_HTTP_LOC_CONF_OFFSET,
        0, 
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_reqstat_module_ctx = {
        NULL,                                   /* preconfiguration */
        ngx_http_reqstat_init,                  /* postconfiguration */

        ngx_http_reqstat_create_main_conf,      /* create main configuration */
        NULL,                                   /* init main configuration */

        NULL,                                   /* create server configuration */
        NULL,                                   /* merge server configuration */

        NULL,                                   /* create location configuration */
        NULL                                    /* merge location configuration */
};

ngx_module_t ngx_http_reqstat_module = {
        NGX_MODULE_V1,
        &ngx_http_reqstat_module_ctx,           /* module context */
        ngx_http_reqstat_commands,              /* module directives */
        NGX_HTTP_MODULE,                        /* module type */
        NULL,                                   /* init master */
        NULL,                                   /* init module */
        NULL,                                   /* init process */
        NULL,                                   /* init thread */
        NULL,                                   /* exit thread */
        NULL,                                   /* exit process */
        NULL,                                   /* exit master */
        NGX_MODULE_V1_PADDING
};

static void *
ngx_http_reqstat_create_main_conf (ngx_conf_t *cf) {
    return ngx_pcalloc(cf->pool, sizeof(ngx_http_reqstat_main_conf_t));
}

static ngx_int_t
ngx_http_reqstat_log_handler (ngx_http_request_t *r) {

    time_t                              now;
    u_char                              key[KLEN];
    u_char                              *p;
    uint32_t                            hash, port;
    ngx_uint_t                          i, len;
    ngx_time_t                         *tp;
    ngx_msec_int_t                      ms;
    ngx_shm_zone_t                     *shm_zone;
    ngx_connection_t                   *c;
    struct sockaddr_in                 *sin;
    ngx_http_reqstat_item_t            *it;
    ngx_http_reqstat_shm_head_t        *hdr;
    ngx_http_reqstat_main_conf_t       *smcf;

    smcf = ngx_http_get_module_main_conf(r, ngx_http_reqstat_module);
    shm_zone = smcf->reqstat_zone;

    c   = r->connection;
    it  = SHM_DATA(shm_zone);
    hdr = SHM_LOCKER(shm_zone);

    ngx_memset(key, 0, sizeof(key));

    port = ntohs(((struct sockaddr_in *)c->local_sockaddr)->sin_port);

    sin = (struct sockaddr_in *) c->local_sockaddr;
    p = (u_char *) &sin->sin_addr;
    ngx_sprintf(key, "%ud.%ud.%ud.%ud:%d", p[0], p[1], p[2], p[3], port);

    len = ngx_strlen(key);

    /*hash*/
    hash = ngx_crc32_short(key, len);

    for (i = 0; i < smcf->nsrv; i++, it++) {
        if (hash == it->hash && !ngx_strncmp(it->key, key, len)) break;
    }

    /*not found.*/
    if (i == smcf->nsrv) {
        return NGX_ERROR;
    }

    /*lock or maybe not.*/
    ngx_shmtx_lock(&hdr->mutex);

    /*bytes.*/
    (void) ngx_atomic_fetch_add(REQSTAT_FIELD_BYTES_IN(it), c->nread);    
    (void) ngx_atomic_fetch_add(REQSTAT_FIELD_BYTES_OUT(it), c->sent);    

    (void) ngx_atomic_fetch_add(REQSTAT_FIELD_CONN_TOTAL(it), 1);
    *REQSTAT_FIELD_CONN_ING(it)   = *ngx_stat_active;
    *REQSTAT_FIELD_REQ_ING(it)    = *ngx_stat_reading + *ngx_stat_writing + 1;

    /*conn & req rate.*/
    ngx_time_update();
    now = ngx_time();
    if (now == it->tm) {
        (void) ngx_atomic_fetch_add(REQSTAT_FIELD_CONN_RATE(it), 1);    
        (void) ngx_atomic_fetch_add(REQSTAT_FIELD_REQ_RATE(it), 1);
    } else {
        *REQSTAT_FIELD_CONN_RATE_PREV(it) = *REQSTAT_FIELD_CONN_RATE(it);
        *REQSTAT_FIELD_CONN_RATE(it) = 1;
        *REQSTAT_FIELD_REQ_RATE_PREV(it) = *REQSTAT_FIELD_REQ_RATE(it);
        *REQSTAT_FIELD_REQ_RATE(it) = 1;
        it->tm = now;
    } 

    /*time elapse*/
    tp = ngx_timeofday();
    ms = (ngx_msec_int_t)((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));

    /*rt_max*/
    if ((ngx_uint_t)ms > *REQSTAT_FIELD_RT_MAX(it)) 
        *REQSTAT_FIELD_RT_MAX(it) = ms;
    
    /*rt_min*/
    if ((ngx_uint_t)ms < *REQSTAT_FIELD_RT_MIN(it))
        *REQSTAT_FIELD_RT_MIN(it) = ms;
    
    /*rt_avr*/    
    *REQSTAT_FIELD_RT_AVR(it) = ( (*REQSTAT_FIELD_RT_AVR(it)) * (*REQSTAT_FIELD_REQ_TOTAL(it)) + ms ) / \
                                                (*REQSTAT_FIELD_REQ_TOTAL(it) + 1) ;
    
    (void) ngx_atomic_fetch_add(REQSTAT_FIELD_REQ_TOTAL(it), 1);    
    
    /*unlock*/
    ngx_shmtx_unlock(&hdr->mutex);

    return 0;
}

static ngx_int_t
ngx_http_reqstat_init_shmzone (ngx_shm_zone_t *shm_zone, void *data) {

    size_t                              size;
    uint32_t                            hash;
    ngx_uint_t                          i;
    ngx_listening_t                    *ls;
    ngx_http_reqstat_ctx_t             *ctx;
    ngx_http_reqstat_item_t            *it;
    ngx_http_reqstat_shm_head_t        *hdr;
    ngx_http_reqstat_main_conf_t       *smcf;

    ctx  = shm_zone->data;
    smcf = ngx_http_cycle_get_module_main_conf(ctx->cycle, ngx_http_reqstat_module);
    hdr  = SHM_HEAD(shm_zone);

    if (ngx_shmtx_create(&hdr->mutex, &hdr->shmtx, NULL) != NGX_OK) {
        return NGX_ERROR;    
    }
    smcf->data = SHM_DATA(shm_zone);
    size = sizeof(ngx_http_reqstat_item_t) * smcf->nsrv;
    it = SHM_DATA(shm_zone);

    ngx_memzero(it, size);
    ls = smcf->cycle->listening.elts;
    for (i = 0; i < smcf->cycle->listening.nelts; i++) {
        hash = ngx_crc32_short(ls[i].addr_text.data, ls[i].addr_text.len);
        it[i].hash = hash;
        ngx_memcpy(it[i].key, ls[i].addr_text.data, ls[i].addr_text.len);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_reqstat_init (ngx_conf_t *cf) {

    size_t                              size;
    ngx_uint_t                          i, nsrv;
    ngx_shm_zone_t                     *shm_zone;
    ngx_core_conf_t                    *ccf;
    ngx_http_handler_pt                *h;
    ngx_http_conf_port_t               *port;
    ngx_http_reqstat_ctx_t             *ctx;
    ngx_http_core_main_conf_t          *cmcf;
    ngx_http_reqstat_main_conf_t       *smcf;

    ccf  = (ngx_core_conf_t *) ngx_get_conf(cf->cycle->conf_ctx, ngx_core_module);
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    smcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_reqstat_module);

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_reqstat_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    ctx->cycle = cf->cycle;

    nsrv = 0;
    if (cmcf->ports) {
        port = cmcf->ports->elts;
        for (i = 0; i < cmcf->ports->nelts; i++) {
            nsrv += port[i].addrs.nelts;
        }
    }

    size = ngx_align(sizeof(ngx_http_reqstat_shm_head_t), 128) + nsrv * sizeof(ngx_http_reqstat_item_t) ;

    shm_zone = ngx_shared_memory_add(cf, &shm_name, size, &ngx_http_reqstat_module);
    if (shm_zone == NULL) {
        return NGX_ERROR;
    }

    shm_zone->init = ngx_http_reqstat_init_shmzone;
    shm_zone->data = ctx;
    smcf->reqstat_zone = shm_zone;
    smcf->workers  = ccf->worker_processes;
    smcf->nsrv     = nsrv;
    smcf->cycle    = cf->cycle;
    
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_reqstat_log_handler; 

    return NGX_OK;
}

static ngx_int_t 
ngx_http_reqstat_show_handler (ngx_http_request_t *r) {

    ngx_int_t                           rc;
    ngx_buf_t                          *b;
    ngx_uint_t                          i, j;
    ngx_chain_t                        *tl, *free;
    ngx_shm_zone_t                     *shm_zone;
    ngx_connection_t                   *c;
    ngx_http_reqstat_item_t            *it;
    ngx_http_reqstat_main_conf_t       *smcf;

    smcf = ngx_http_get_module_main_conf(r, ngx_http_reqstat_module);
    shm_zone = smcf->reqstat_zone;
    it   = SHM_DATA(shm_zone);
    c    = r->connection;
    free = NULL;

    r->headers_out.status = NGX_HTTP_OK;
    ngx_http_clear_content_length(r);
    
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
    
    tl = ngx_chain_get_free_buf(r->pool, &free);
    if (tl == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b = tl->buf;
    b->start = ngx_pcalloc(r->pool, BUFSIZ);
    if (b->start == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->end = b->start + BUFSIZ;
    b->last = b->pos = b->start;
    b->memory = 1;
    b->temporary = 1;

    b->last = ngx_slprintf(b->last, b->end, "%uA\n", smcf->workers);
    
    for (i = 0; i < smcf->nsrv; i++, it++) {

        b->last = ngx_slprintf(b->last, b->end, "%s,FRONTEND,", it->key);

        for (j = 0; j < sizeof(fields) / sizeof(ngx_http_reqstat_field_t); j++) {
            ngx_uint_t *p = ZONE(it, fields[j].offset);
            b->last = ngx_slprintf(b->last, b->end, "%uA,", *p);
        }

        *(b->last - 1) = '\n'; 
    }

    b->last_buf = 1;

    if (ngx_http_output_filter(r, tl) == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}

static char *
ngx_http_reqstat_show (ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

    ngx_http_core_loc_conf_t           *clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_reqstat_show_handler;

    return NULL;
}
