#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_BARRIER_BUF_LEN   256
#define NGX_BARRIER_RULE_NUM  100


typedef struct {
  ngx_flag_t      enable;  
  ngx_shm_zone_t  *shm_zone;
  ngx_uint_t      burst;
  ngx_uint_t      nodelay;   
} ngx_http_barrier_conf_t;


typedef struct {
  in_addr_t       mask;
  in_addr_t       addr;
  ngx_uint_t      black; 
} ngx_http_barrier_rule_t;


#if (NGX_HAVE_INET6)
typedef struct {
  struct in6_addr   mask;
  struct in6_addr   addr;  
  ngx_uint_t        black;
} ngx_http_barrier_rule6_t;
#endif


typedef struct {
  ngx_rbtree_t       rbtree;
  ngx_rbtree_node_t  sentinel;
  ngx_queue_t        queue;
} ngx_http_barrier_shctx_t;


typedef struct {
  ngx_http_barrier_shctx_t  *sh;
  ngx_slab_pool_t           *shpool;
  ngx_uint_t       interval;   //time interval
  ngx_uint_t       freq;       //barrier freq
  ngx_uint_t       freeze;     //freeze  time 
  ngx_uint_t       timeout;    //timeout time
  ngx_hash_init_t  BWlist;     //black-white list
  ngx_array_t      *rules;     //black-white network segment
#if (NGX_HAVE_INET6)
  ngx_array_t      *rules6;    //black-white network segment
#endif
  ngx_int_t        index;
  ngx_str_t        var;
} ngx_http_barrier_ctx_t;


typedef struct {
  u_char         color;
  u_char         dummy;
  u_short        len;
  ngx_queue_t    queue;
  ngx_msec_t     last;         //last access timestamp
  ngx_int_t      awake;        //awake time 
  ngx_uint_t     count;        //request count  
  u_char         data[1];
} ngx_http_barrier_node_t;


static ngx_int_t ngx_http_barrier_inet(ngx_http_request_t *r, ngx_http_barrier_ctx_t *ctx, in_addr_t addr);
#if (NGX_HAVE_INET6)
static ngx_int_t ngx_http_barrier_inet6(ngx_http_request_t *r, ngx_http_barrier_ctx_t *ctx, u_char *p);
#endif
static ngx_int_t ngx_http_barrier_find_BWlist(ngx_http_request_t *r, ngx_http_barrier_ctx_t *ctx);
static void ngx_http_barrier_expire(ngx_http_barrier_ctx_t *ctx, ngx_uint_t n);
static ngx_int_t ngx_http_barrier_lookup(ngx_http_barrier_conf_t *lrcf, ngx_log_t *log, ngx_uint_t hash, u_char *data, size_t len, ngx_uint_t *again);
static void ngx_http_barrier_delay(ngx_http_request_t *r);
ngx_int_t ngx_http_barrier_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_barrier_init_BWlist(ngx_conf_t *cf, ngx_http_barrier_ctx_t  *ctx, ngx_str_t file);
static void ngx_http_barrier_rbtree_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_int_t ngx_http_barrier_init_zone(ngx_shm_zone_t *shm_zone, void *data);
static char * ngx_http_barrier_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char * ngx_http_barrier(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_global_barrier_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void * ngx_http_barrier_create_conf(ngx_conf_t *cf);
static char * ngx_http_barrier_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_barrier_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_barrier_commands[] = 
{
	{ ngx_string("global_barrier"),
    NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
    ngx_http_global_barrier_enable,
    NGX_HTTP_SRV_CONF_OFFSET,
    offsetof(ngx_http_barrier_conf_t, enable),
    NULL 
  },
  
  { ngx_string("barrier_zone"),
    NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE7,
    ngx_http_barrier_zone,
    0,
    0,
    NULL
  },

  { ngx_string("barrier"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE123,
    ngx_http_barrier,
    NGX_HTTP_SRV_CONF_OFFSET,
    0,
    NULL 
  },

  ngx_null_command
};


static ngx_http_module_t  ngx_http_barrier_module_ctx = 
{
  NULL,                             /* preconfiguration */
  ngx_http_barrier_init,            /* postconfiguration */

  NULL,                             /* create main configuration */
  NULL,                             /* init main configuration */

  ngx_http_barrier_create_conf,     /* create server configuration */
  ngx_http_barrier_merge_conf,      /* merge server configuration */

  NULL,                             /* create location configration */
  NULL                              /* merge location configration */
};


ngx_module_t  ngx_http_barrier_module = {
  NGX_MODULE_V1,
  &ngx_http_barrier_module_ctx,          /* module context */
  ngx_http_barrier_commands,             /* module directives */
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
                   ngx_http_barrier_handler
***************************************************************************************/
static ngx_int_t ngx_http_barrier_inet(ngx_http_request_t *r, ngx_http_barrier_ctx_t *ctx, in_addr_t addr)
{
  ngx_uint_t  i;
  ngx_http_barrier_rule_t  *rule;

  rule = ctx->rules->elts;
  for (i=0; i<ctx->rules->nelts; i++) {
  	if ((addr & rule[i].mask) == rule[i].addr) {    
  	  if (rule[i].black == 1){
  	     return  NGX_HTTP_FORBIDDEN;  
  	  }else if (rule[i].black == 0){
  	     return  NGX_OK;       
  	  }
    }    
  }
  return NGX_DECLINED;
}


#if (NGX_HAVE_INET6)
static ngx_int_t ngx_http_barrier_inet6(ngx_http_request_t *r, ngx_http_barrier_ctx_t *ctx, u_char *p)
{
  ngx_uint_t   i, n;
  ngx_http_barrier_rule6_t  *rule6;

  rule6 = ctx->rules6->elts;
  for(i=0; i<ctx->rules6->nelts; i++) {
    for(n = 0; n < 16; n++) {
      if ((p[n] & rule6[i].mask.s6_addr[n]) != rule6[i].addr.s6_addr[n]) {
        goto next;
      }
    }
    
    if (rule6[i].black == 1){
  	  return  NGX_HTTP_FORBIDDEN;  
  	}else if (rule6[i].black == 0){
  	  return  NGX_OK;       
  	}

    next:
      continue;
  }
  return NGX_DECLINED;
}
#endif


static ngx_int_t ngx_http_barrier_find_BWlist(ngx_http_request_t *r, ngx_http_barrier_ctx_t *ctx)
{
  ngx_uint_t key;
  u_char     *find;
  u_char     *address;
  struct sockaddr_in  *sin;
  ngx_hash_init_t *hash_init = &ctx->BWlist;  

  sin = (struct sockaddr_in *) r->connection->sockaddr;
  address = inet_ntoa(sin->sin_addr);
  
  key = ngx_hash_key_lc(address, strlen(address));   
  find = ngx_hash_find(hash_init->hash, key, address, strlen(address)); 
  if (find) {  
    if (strcmp(find, "black") == 0){
      return NGX_HTTP_FORBIDDEN; 
    }else if (strcmp(find, "white") == 0){
      return NGX_OK ;       
    }
  } 
 
#if (NGX_HAVE_INET6)
  if (ctx->rules6 && r->connection->sockaddr->sa_family == AF_INET6) {
    u_char               *p;
    in_addr_t             addr;
    struct sockaddr_in6  *sin6;

    sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
    p = sin6->sin6_addr.s6_addr;

    if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
      addr = p[12] << 24;
      addr += p[13] << 16;
      addr += p[14] << 8;
      addr += p[15];
      return ngx_http_barrier_inet(r, ctx, htonl(addr));
    }
    return ngx_http_barrier_inet6(r, ctx, p);
  }
#endif 

  if (ctx->rules && r->connection->sockaddr->sa_family == AF_INET) {
    sin = (struct sockaddr_in *) r->connection->sockaddr;
    return ngx_http_barrier_inet(r, ctx, sin->sin_addr.s_addr);
  }
  return NGX_DECLINED;          		
}


static void ngx_http_barrier_expire(ngx_http_barrier_ctx_t *ctx, ngx_uint_t n)
{
  ngx_time_t     *tp;
  ngx_msec_t     now;
  ngx_queue_t    *q;
  ngx_msec_int_t     ms;
  ngx_rbtree_node_t  *node;
  ngx_http_barrier_node_t  *lr;

  tp = ngx_timeofday();
  now = (ngx_msec_t) (tp->sec * 1000 + tp->msec);

  //n == 1: deletes one or two zero rate entries
  //n == 0: deletes oldest entry by force and one or two zero rate entries
  while (n < 3) {
    if (ngx_queue_empty(&ctx->sh->queue)) {
      return;
    }

    q = ngx_queue_last(&ctx->sh->queue);
    lr = ngx_queue_data(q, ngx_http_barrier_node_t, queue);
    if (n++ != 0) {
      ms = (ngx_msec_int_t) (now - lr->last);
      ms = ngx_abs(ms);
      if (ms < (ngx_msec_int_t )ctx->timeout) {
        return;
      }  
    }
    ngx_queue_remove(q);
    node = (ngx_rbtree_node_t *)((u_char *) lr - offsetof(ngx_rbtree_node_t, color));
    ngx_rbtree_delete(&ctx->sh->rbtree, node);
    ngx_slab_free_locked(ctx->shpool, node);
  }
}


static ngx_int_t ngx_http_barrier_lookup(ngx_http_barrier_conf_t *lrcf, ngx_log_t *log, ngx_uint_t hash, u_char *data, size_t len, ngx_uint_t *again)
{
  ngx_int_t       rc, excess;
  ngx_time_t      *tp;
  ngx_msec_t      now;
  ngx_msec_int_t  ms;
  ngx_rbtree_node_t        *node, *sentinel;
  ngx_http_barrier_ctx_t   *ctx;
  ngx_http_barrier_node_t  *lr;

  ctx = lrcf->shm_zone->data;
  node = ctx->sh->rbtree.root;
  sentinel = ctx->sh->rbtree.sentinel;

  while (node != sentinel) {
    if (hash < node->key) {
      node = node->left;
      continue;
    }

    if (hash > node->key) {
      node = node->right;
      continue;
    }

    /* hash == node->key */
    do {
      lr = (ngx_http_barrier_node_t *) &node->color;
      
      rc = ngx_memn2cmp(data, lr->data, len, (size_t) lr->len);
      if (rc == 0) {
        ngx_queue_remove(&lr->queue);
        ngx_queue_insert_head(&ctx->sh->queue, &lr->queue);

        tp = ngx_timeofday();
        now = (ngx_msec_t) (tp->sec * 1000 + tp->msec);
        ms = (ngx_msec_int_t) (now - lr->last);
        ms = ngx_abs(ms);
		
        excess = lr->count - ctx->freq;
              
        //busy situation
        lr->awake -= ms;
        if (lr->awake <= 0 ){
          lr->awake = 0;
        }else{
        	ngx_log_error(NGX_LOG_ERR, log, 0, "[BUSYing]: now = %d, last = %d, ms = %d, awake = %d", now, lr->last, ms, lr->awake);
        	lr->last = now;        	
          return NGX_BUSY;          	
        }

        //other situation
        if (ms < (ngx_msec_int_t) ctx->interval){
        	if (excess <= 0){
        	  lr->count += 1;
        	  //ngx_log_error(NGX_LOG_ERR, log, 0, "[IDLE]: ms = %d, count = %d", ms, lr->count);
        	  return NGX_OK;
        	}else{
        		if ((ngx_uint_t) (lr->count * ctx->interval) > (lrcf->burst * ctx->freq * ms)) {
        			 ngx_log_error(NGX_LOG_ERR, log, 0, "[BUSY]: now = %d, last = %d, ms = %d, count = %d", now, lr->last, ms, lr->count);
        			 lr->last = now;
        			 lr->awake = ctx->freeze;
        			 lr->count = 0;        			 
        			 return NGX_BUSY;
            }else{
            	 ngx_log_error(NGX_LOG_ERR, log, 0, "[AGAIN]: ms = %d, count = %d", ms, lr->count);
               lr->count += 1;
               *again = ctx->interval - ms;                
               return NGX_AGAIN;	
            }      		
        	}       	
        }else{   //time is reached
        	 //ngx_log_error(NGX_LOG_ERR, log, 0, "[IDLE-reset]: ms = %d, count = %d", ms, lr->count);
        	 lr->last = now;
        	 lr->count = 0;       	 
        	 lr->awake = 0; 	        		         	
        	 return NGX_OK;
        }

      }
      node = (rc < 0) ? node->left : node->right;
    } while (node != sentinel && hash == node->key);
        break;
    }

    *again = 0;
    return NGX_DECLINED;
}


static void ngx_http_barrier_delay(ngx_http_request_t *r)
{
  ngx_event_t  *wev;

  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "barrier delay");

  wev = r->connection->write;
  if (!wev->timedout) {
    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    return;
  }
  wev->timedout = 0;

  if (ngx_handle_read_event(r->connection->read, 0) != NGX_OK) {
    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    return;
  }

  r->read_event_handler = ngx_http_block_reading;
  r->write_event_handler = ngx_http_core_run_phases;

  ngx_http_core_run_phases(r);
}


ngx_int_t ngx_http_barrier_handler(ngx_http_request_t *r)
{
  size_t      len, n;
  uint32_t    hash;
  ngx_int_t   rc;
  ngx_uint_t  again, status;
  ngx_time_t  *tp;
  ngx_rbtree_node_t          *node;
  ngx_http_variable_value_t  *vv;
  ngx_http_barrier_ctx_t     *ctx = NULL;
  ngx_http_barrier_node_t    *lr;
  ngx_http_barrier_conf_t    *lrcf;  
  ngx_http_request_t tmpr;
  ngx_http_core_main_conf_t  *cmcf;
  ngx_http_variable_value_t  *variables;
    
  lrcf = ngx_http_get_module_srv_conf(r, ngx_http_barrier_module);
  if (lrcf->shm_zone == NULL) {
    return NGX_DECLINED;  
  }
  
  //global_barrier=off && before ssl shakehand
  if(r->pool == NULL && !lrcf->enable) {	
    return NGX_DECLINED;
  }    

  ctx = lrcf->shm_zone->data;
  status = ngx_http_barrier_find_BWlist(r, ctx);
  if (status == NGX_HTTP_FORBIDDEN){
  	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[black list]: access forbidden by rule");
    return NGX_HTTP_FORBIDDEN;	
  }else if(status == NGX_OK){
  	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[white list]: access allowed by rule");
    return NGX_DECLINED;	 	
  }
 	
  tmpr = *r;
  cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
  if(r->pool == NULL && lrcf->enable) {		
    	variables = ngx_pcalloc(r->connection->pool, cmcf->variables.nelts * sizeof(ngx_http_variable_value_t)); 
		  tmpr.variables = variables;
  }

  vv = ngx_http_get_indexed_variable(&tmpr, ctx->index);
  if (vv == NULL || vv->not_found) {
    return NGX_DECLINED;
  }
  
  len = vv->len;
  if (len == 0) {
    return NGX_DECLINED;
  }
  if (len > 65535) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "the value of the \"%V\" variable " "is more than 65535 bytes: \"%v\"", &ctx->var, vv);
    return NGX_DECLINED;
  }

  hash = ngx_crc32_short(vv->data, len);
  ngx_shmtx_lock(&ctx->shpool->mutex);
  
  ngx_http_barrier_expire(ctx, 1);
  rc = ngx_http_barrier_lookup(lrcf, r->connection->log, hash, vv->data, len, &again);
  if (rc == NGX_DECLINED) {
    n = offsetof(ngx_rbtree_node_t, color) + offsetof(ngx_http_barrier_node_t, data) + len;
    node = ngx_slab_alloc_locked(ctx->shpool, n);
    if (node == NULL) {
      ngx_http_barrier_expire(ctx, 0);

      node = ngx_slab_alloc_locked(ctx->shpool, n);
      if (node == NULL) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return NGX_HTTP_SERVICE_UNAVAILABLE;
      }
    }

    lr = (ngx_http_barrier_node_t *) &node->color;

    node->key = hash;
    lr->len = (u_char) len;

    tp = ngx_timeofday();
    lr->last = (ngx_msec_t) (tp->sec * 1000 + tp->msec);
    lr->count = 1;
    lr->awake = 0;
    ngx_memcpy(lr->data, vv->data, len);

    ngx_rbtree_insert(&ctx->sh->rbtree, node);
    ngx_queue_insert_head(&ctx->sh->queue, &lr->queue);
    ngx_shmtx_unlock(&ctx->shpool->mutex);
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[IDLE]: system is in idle status");
    return NGX_DECLINED;
  }
  
  ngx_shmtx_unlock(&ctx->shpool->mutex);
  
  if (rc == NGX_OK) {
  	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[IDLE]: system is in idle status");
    return NGX_DECLINED;
  }

  if (rc == NGX_BUSY) { 	
    return NGX_HTTP_SERVICE_UNAVAILABLE;
  }
  
  
  /* rc == NGX_AGAIN */ 
  if (lrcf->enable){
    return NGX_DECLINED; 	
  }
   
  if (lrcf->nodelay) {
    return NGX_DECLINED;
  }

  if (ngx_handle_read_event(r->connection->read, 0) != NGX_OK) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  r->read_event_handler = ngx_http_test_reading;
  r->write_event_handler = ngx_http_barrier_delay;
  
  ngx_add_timer(r->connection->write, again);

  return NGX_AGAIN;
}

/*************************************************************************************
                   ngx_command_t  ngx_http_barrier_commands
***************************************************************************************/
static ngx_int_t ngx_http_barrier_init_BWlist(ngx_conf_t *cf, ngx_http_barrier_ctx_t  *ctx, ngx_str_t file)
{  
	 FILE *fp;	
	 u_char  *p, buf[NGX_BARRIER_BUF_LEN], value[NGX_BARRIER_BUF_LEN], key[NGX_BARRIER_BUF_LEN];
	 ngx_hash_t       *hash;
	 ngx_hash_key_t   *node;
	 ngx_array_t      *datas;
	 ngx_hash_init_t  *hash_init = &ctx->BWlist;
	 ngx_pool_t       *pool  = cf->pool;
	 
	 //network segment
	 ngx_int_t        rc, num;
	 ngx_cidr_t       cidr;
	 ngx_str_t        network;	 

	 ngx_http_barrier_rule_t  *rule;
#if (NGX_HAVE_INET6)
   ngx_http_barrier_rule666666_t  *rule6;
#endif
	 
	 num = 0;	 
	 network.data = ngx_palloc(pool, NGX_BARRIER_BUF_LEN);
	 if (network.data == NULL){
	   return NGX_ERROR;	
	 } 
	 
   fp = fopen(file.data, "r");
   if (fp == NULL){
   	 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Black-White list file %s not exist", file.data);
     return NGX_ERROR;
   }

   datas = ngx_array_create(pool, NGX_BARRIER_RULE_NUM, sizeof(ngx_hash_key_t)); 
   if (datas == NULL){
   	 fclose(fp);
   	 return NGX_ERROR;
   }
     
   while(1)
   {
    	memset(buf, 0, NGX_BARRIER_BUF_LEN);
    	memset(key, 0, NGX_BARRIER_BUF_LEN);
    	memset(value, 0, NGX_BARRIER_BUF_LEN);
    	memset(network.data, 0, NGX_BARRIER_BUF_LEN);
    	memset(&cidr, 0, sizeof(ngx_cidr_t));
    	
    	p = fgets(buf, NGX_BARRIER_BUF_LEN, fp);
    	if (p == NULL){
    		break;	
    	}
    	
    	sscanf(buf, "%[^ ]%s", value, key);    	    	
    	if ((strcmp(value, "black")!=0) && (strcmp(value, "white")!= 0)){
    		continue;
    	}else{
    	   	num += 1;    	   	
    	   	if (strchr(key, '/') != NULL){   	   		
    	   		network.len = strlen(key);  	   		
    	   		strncpy(network.data, key, network.len);
    	   		network.data[network.len] = '\0';
    	   		
    	   		rc = ngx_ptocidr(&network, &cidr);
    	   		if (rc == NGX_ERROR){
    	   		  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter %s", key);
    	   		  fclose(fp);
    	   		  return NGX_ERROR;
    	   		}
    	   		if (rc == NGX_DONE){
    	   		  ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "low address bits of %s are meaningless", key);
    	   		}
    	   		
    	   		switch(cidr.family){
            #if (NGX_HAVE_INET6)
               case AF_INET6:
               case 0: 
                 if (ctx->rules6 == NULL) {
                   ctx->rules6 = ngx_array_create(pool, 4, sizeof(ngx_http_barrier_rule6_t));
                   if (ctx->rules6 == NULL) {
                   	 fclose(fp);
                     return NGX_ERROR;
                   }
                 }

                 rule6 = ngx_array_push(ctx->rules6);
                 if (rule6 == NULL) {
                 	 fclose(fp);
                   return NGX_ERROR;
                 }

                 rule6->mask = cidr.u.in6.mask;
                 rule6->addr = cidr.u.in6.addr;
                 rule6->black = (strcmp(value,"black") == 0) ? 1 : 0;
            #endif
            
               default: /* AF_INET */
                 if (ctx->rules == NULL) {
                   ctx->rules = ngx_array_create(pool, 4, sizeof(ngx_http_barrier_rule_t));
                   if (ctx->rules == NULL) {
                   	 fclose(fp);
                     return NGX_ERROR;
                   }
                 }

                 rule = ngx_array_push(ctx->rules);
                 if (rule == NULL) {
                 	 fclose(fp);
                   return NGX_ERROR;
                 }

                 rule->mask = cidr.u.in.mask;
                 rule->addr = cidr.u.in.addr;
                 rule->black = (strcmp(value,"black") == 0) ? 1 : 0;    	   			    	   			   	   			
    	   	  } //switch ends    	   		
    	   	}else{//if not network segment    	   		
    	   	  node = (ngx_hash_key_t *)ngx_array_push(datas);
    	     	node->key.len = strlen(key);
            node->key.data = ngx_pcalloc(pool, NGX_BARRIER_BUF_LEN);
    	     	strncpy(node->key.data, key, node->key.len); 
    	     	node->key.data[node->key.len] = '\0';	
 	
    	     	node->key_hash = ngx_hash_key_lc(node->key.data, node->key.len);
    	     	node->value = (char *)ngx_pcalloc(pool, NGX_BARRIER_BUF_LEN);
    	     	if (node->value == NULL){
    	     		fclose(fp);
    	     	  return NGX_ERROR;	
    	     	} 
    	     	strncpy((char * )node->value, value, strlen(value));
    	   }
      }    	    		 
   }//while ends

   hash = (ngx_hash_t *)ngx_pcalloc(pool, sizeof(ngx_hash_t));
   if (hash == NULL){
   	  fclose(fp);
      return NGX_ERROR;
   }
   hash_init->hash = hash;
   hash_init->key = &ngx_hash_key_lc;
   hash_init->max_size = NGX_BARRIER_RULE_NUM*10;
   hash_init->bucket_size = 64;
   hash_init->name = "barrier_rule_hash";
   hash_init->pool = pool;
   hash_init->temp_pool = NULL;
   if (ngx_hash_init(hash_init, (ngx_hash_key_t *)datas->elts, datas->nelts) != NGX_OK){
      fclose(fp);
      return NGX_ERROR;	
   }
   
   fclose(fp);
   return NGX_OK;		
}


static void ngx_http_barrier_rbtree_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
  ngx_rbtree_node_t         **p;
  ngx_http_barrier_node_t   *lrn, *lrnt;

  for ( ;; ) {
    if (node->key < temp->key) {
      p = &temp->left;
    } else if (node->key > temp->key) {
      p = &temp->right;
    } else { /* node->key == temp->key */
      lrn = (ngx_http_barrier_node_t *) &node->color;
      lrnt = (ngx_http_barrier_node_t *) &temp->color;
      p = (ngx_memn2cmp(lrn->data, lrnt->data, lrn->len, lrnt->len) < 0) ? &temp->left : &temp->right;
    }

    if (*p == sentinel) {
      break;
    }

    temp = *p;
  }

  *p = node;
  node->parent = temp;
  node->left = sentinel;
  node->right = sentinel;
  ngx_rbt_red(node);
}


static ngx_int_t ngx_http_barrier_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
  ngx_http_barrier_ctx_t  *octx = data;  
  ngx_http_barrier_ctx_t  *ctx  = shm_zone->data;;
  size_t len;

  if (octx) {
    if (ngx_strcmp(ctx->var.data, octx->var.data) != 0) {
      ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0, "barrier \"%V\" uses the \"%V\" variable " "while previously it used the \"%V\" variable", &shm_zone->shm.name, &ctx->var, &octx->var);
      return NGX_ERROR;
    }

    ctx->sh = octx->sh;
    ctx->shpool = octx->shpool;

    return NGX_OK;
  }

  ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
  if (shm_zone->shm.exists) {
    ctx->sh = ctx->shpool->data;
    return NGX_OK;
  }

  ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_barrier_shctx_t));
  if (ctx->sh == NULL) {
    return NGX_ERROR;
  }

  ctx->shpool->data = ctx->sh;

  ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel, ngx_http_barrier_rbtree_insert_value);
  ngx_queue_init(&ctx->sh->queue);

  len = sizeof(" in barrier zone \"\"") + shm_zone->shm.name.len;

  ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
  if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
  }

  ngx_sprintf(ctx->shpool->log_ctx, " in barrier zone \"%V\"%Z", &shm_zone->shm.name);

  return NGX_OK;
}


static char * ngx_http_barrier_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  u_char      *p;
  ngx_uint_t  i;   
  size_t      size, len; 
  ngx_str_t   *value, name, s, BWfile;
  ngx_int_t   interval, scale, freq, freeze, timeout;  
  ngx_shm_zone_t          *shm_zone;
  ngx_http_barrier_ctx_t  *ctx;

  value = cf->args->elts;

  ctx = NULL;
  name.len = 0;
  size = 0;
  interval = 1;
  scale = 1;
  freq = 0;
  freeze = 0;
  timeout = 0;
  
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
        if (size > 8191) {
          continue;
        }
      }

      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid zone size \"%V\"", &value[i]);
      return NGX_CONF_ERROR;
    }

    if (ngx_strncmp(value[i].data, "interval=", 9) == 0) {
      len = value[i].len;
      p = value[i].data + len - 1;
      if (ngx_strncmp(p, "s", 1) == 0) {
        scale = 1;
        len -= 1;
      }else if (ngx_strncmp(p, "m", 1) == 0) {
        scale = 60;
        len -= 1;
      }else if (ngx_strncmp(p, "h", 1) == 0) {
        scale = 60*60;
        len -= 1;
      }

      interval = ngx_atoi(value[i].data + 9, len - 9);
      interval *= scale * 1000; 
      if (interval <= NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid interval \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
      }
      continue;
    }
    
    if (ngx_strncmp(value[i].data, "freq=", 5) == 0) {
      len = value[i].len;
      p = value[i].data + len - 1;

      freq = ngx_atoi(value[i].data + 5, len - 5);
      if (freq <= NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid freq \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
      }
      continue;
    }


    if (ngx_strncmp(value[i].data, "freeze=", 7) == 0) {
      len = value[i].len;
      p = value[i].data + len - 1;
      if (ngx_strncmp(p, "s", 1) == 0) {
        scale = 1;
        len -= 1;
      }else if (ngx_strncmp(p, "m", 1) == 0) {
        scale = 60;
        len -= 1;
      }else if (ngx_strncmp(p, "h", 1) == 0) {
        scale = 60*60;
        len -= 1;
      }

      freeze = ngx_atoi(value[i].data + 7, len - 7);
      freeze *= scale * 1000; 
      if (freeze <= NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid freeze \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
      }
      continue;
    }
    
    if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {
      len = value[i].len;
      p = value[i].data + len - 1;
      if (ngx_strncmp(p, "s", 1) == 0) {
        scale = 1;
        len -= 1;
      }else if (ngx_strncmp(p, "m", 1) == 0) {
        scale = 60;
        len -= 1;
      }else if (ngx_strncmp(p, "h", 1) == 0) {
        scale = 60*60;
        len -= 1;
      }

      timeout = ngx_atoi(value[i].data + 8, len - 8);
      timeout *= scale * 1000; 
      if (timeout <= NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid timeout \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
      }
      continue;
    }
    
    if (ngx_strncmp(value[i].data, "BWlist=", 7) == 0) {
    	BWfile.len = value[i].len;
    	BWfile.data = value[i].data + 7;
    	continue;
    }
       
    if (value[i].data[0] == '$') {
      value[i].len--;
      value[i].data++;

      ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_barrier_ctx_t));
      if (ctx == NULL) {
        return NGX_CONF_ERROR;
      }

      ctx->index = ngx_http_get_variable_index(cf, &value[i]);
      if (ctx->index == NGX_ERROR) {
        return NGX_CONF_ERROR;
      }
      ctx->var = value[i];
      continue;
    }
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[i]);
    return NGX_CONF_ERROR;
  }  //for ends

  if (name.len == 0 || size == 0) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" must have \"zone\" parameter", &cmd->name);
    return NGX_CONF_ERROR;
  }

  if (ctx == NULL) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "no variable is defined for barrier_zone \"%V\"", &cmd->name);
    return NGX_CONF_ERROR;
  }

  ctx->interval = interval;
  ctx->freq = freq;
  ctx->freeze = freeze;
  ctx->timeout = timeout;
  if (ngx_http_barrier_init_BWlist(cf, ctx, BWfile) != NGX_OK){
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "BWlist config file error for barrier_zone '%s'", BWfile.data);
    return NGX_CONF_ERROR;  	
  }
  
  shm_zone = ngx_shared_memory_add(cf, &name, size, &ngx_http_barrier_module);
  if (shm_zone == NULL) {
    return NGX_CONF_ERROR;
  }

  if (shm_zone->data) {
    ctx = shm_zone->data;
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "barrier_zone \"%V\" is already bound to variable \"%V\"", &value[1], &ctx->var);
    return NGX_CONF_ERROR;
  }

  shm_zone->init = ngx_http_barrier_init_zone;
  shm_zone->data = ctx;

  return NGX_CONF_OK;
}


static char * ngx_http_barrier(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_barrier_conf_t  *lrcf = conf;
  ngx_int_t    burst;
  ngx_str_t   *value, s;
  ngx_uint_t   i;

  if (lrcf->shm_zone) {
    return "is duplicate";
  }

  value = cf->args->elts;
  burst = 0;

  for (i=1; i < cf->args->nelts; i++) {
    if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {
      s.len = value[i].len - 5;
      s.data = value[i].data + 5;
      lrcf->shm_zone = ngx_shared_memory_add(cf, &s, 0, &ngx_http_barrier_module);
      if (lrcf->shm_zone == NULL) {
        return NGX_CONF_ERROR;
      }
      continue;
    }

    if (ngx_strncmp(value[i].data, "burst=", 6) == 0) {
      burst = ngx_atoi(value[i].data + 6, value[i].len - 6);
      if (burst <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid burst rate \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
      }
      continue;
    }

    if (ngx_strncmp(value[i].data, "nodelay", 7) == 0) {
      lrcf->nodelay = 1;
      continue;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[i]);
    return NGX_CONF_ERROR;
  } //for ends

  if (lrcf->shm_zone == NULL) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" must have \"zone\" parameter", &cmd->name);
    return NGX_CONF_ERROR;
  }

  if (lrcf->shm_zone->data == NULL) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "unknown barrier_zone \"%V\"", &lrcf->shm_zone->shm.name);
    return NGX_CONF_ERROR;
  }

  lrcf->burst = burst;

  return NGX_CONF_OK;
}


static char *ngx_http_global_barrier_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  char  *rv;
  rv = ngx_conf_set_flag_slot(cf, cmd, conf);
  if (rv != NGX_CONF_OK) {
    return rv;
  }

  return NGX_CONF_OK;
}


/*************************************************************************************
                   ngx_http_module_t  ngx_http_barrier_module_ctx
***************************************************************************************/
static void * ngx_http_barrier_create_conf(ngx_conf_t *cf)
{
  ngx_http_barrier_conf_t  *conf;
  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_barrier_conf_t));  //init by pcalloc
  if (conf == NULL) {
    return NULL;
  }
  
  conf->enable = NGX_CONF_UNSET; 
  return conf;
}


static char * ngx_http_barrier_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
  ngx_http_barrier_conf_t *prev = parent;
  ngx_http_barrier_conf_t *conf = child;

  if (conf->shm_zone == NULL){
     *conf = *prev;
  }
  
  ngx_conf_merge_value(conf->enable, prev->enable, 0);  //default is 0
  return NGX_CONF_OK;
}


static ngx_int_t ngx_http_barrier_init(ngx_conf_t *cf)
{
  ngx_http_handler_pt        *h;
  ngx_http_core_main_conf_t  *cmcf;
  ngx_http_barrier_conf_t    *lrcf;
 
  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
  lrcf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_barrier_module);  
   
  if(!lrcf->enable || lrcf->enable == NGX_CONF_UNSET){
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
      return NGX_ERROR;
    }
  
    *h = ngx_http_barrier_handler;
  }
  
  return NGX_OK;
}
