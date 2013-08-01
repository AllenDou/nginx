/* buffer_pool.c */
/*
 * Copyright (c) 2003-2005 Cavium Networks (support@cavium.com). All rights 
 * reserved.
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, 
 * this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 * 
 * 3. All manuals,brochures,user guides mentioning features or use of this software 
 *    must display the following acknowledgement:
 * 
 *   This product includes software developed by Cavium Networks
 * 
 * 4. Cavium Networks' name may not be used to endorse or promote products 
 *    derived from this software without specific prior written permission.
 * 
 * 5. User agrees to enable and utilize only the features and performance 
 *    purchased on the target hardware.
 * 
 * This Software,including technical data,may be subject to U.S. export control 
 * laws, including the U.S. Export Administration Act and its associated 
 * regulations, and may be subject to export or import regulations in other 
 * countries.You warrant that You will comply strictly in all respects with all 
 * such regulations and acknowledge that you have the responsibility to obtain 
 * licenses to export, re-export or import the Software.

 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS" AND 
 * WITH ALL FAULTS AND CAVIUM MAKES NO PROMISES, REPRESENTATIONS OR WARRANTIES, 
 * EITHER EXPRESS,IMPLIED,STATUTORY, OR OTHERWISE, WITH RESPECT TO THE SOFTWARE,
 * INCLUDING ITS CONDITION,ITS CONFORMITY TO ANY REPRESENTATION OR DESCRIPTION, 
 * OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM SPECIFICALLY 
 * DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE, MERCHANTABILITY, 
 * NONINFRINGEMENT,FITNESS FOR A PARTICULAR PURPOSE,LACK OF VIRUSES, ACCURACY OR
 * COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE TO 
 * DESCRIPTION. THE ENTIRE RISK ARISING OUT OF USE OR PERFORMANCE OF THE 
 * SOFTWARE LIES WITH YOU.
 *
 */
#include "cavium_sysdep.h"
#include "cavium_common.h"
#include "cavium_list.h"
#include "cavium.h"
#include "init_cfg.h"
#include "buffer_pool.h"

static struct kmem_cache *extra_buffer_cache=NULL;
static struct kmem_cache *huge_buffer_cache=NULL;
static struct kmem_cache *large_buffer_cache=NULL;
static struct kmem_cache *medium_buffer_cache=NULL;
static struct kmem_cache *small_buffer_cache=NULL;
static struct kmem_cache *tiny_buffer_cache=NULL;
static struct kmem_cache *ex_tiny_buffer_cache=NULL;


struct kmem_cache * 
linux_cache_init(char *name, int size)
{

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
    return kmem_cache_create(name,size,0,0,NULL,NULL);
#else
    return kmem_cache_create(name,size,0,0,NULL);
#endif
}

void* 
linux_cache_alloc(struct kmem_cache *cache)
{
    return kmem_cache_alloc(cache, GFP_ATOMIC);
}	

void 
linux_cache_free(struct kmem_cache *cache, void *entry)
{
    kmem_cache_free(cache, entry);
}	

void 
linux_cache_destroy(struct kmem_cache *cache)
{
    kmem_cache_destroy(cache);
}	
struct kmem_cache * 
get_cache(Uint32 buf_size)
{
    struct kmem_cache *cache = NULL;
    
    if(buf_size <= EX_TINY_BUFFER_CHUNK_SIZE)
        cache = ex_tiny_buffer_cache;
    else if(buf_size <= TINY_BUFFER_CHUNK_SIZE)
        cache = tiny_buffer_cache;
    else if(buf_size <= SMALL_BUFFER_CHUNK_SIZE)
        cache = small_buffer_cache;
    else if(buf_size <= MEDIUM_BUFFER_CHUNK_SIZE)
        cache = medium_buffer_cache;
    else if(buf_size <= LARGE_BUFFER_CHUNK_SIZE)
        cache = large_buffer_cache;
    else if(buf_size <= HUGE_BUFFER_CHUNK_SIZE)
        cache = huge_buffer_cache;
    else if(buf_size <= EXTRA_BUFFER_CHUNK_SIZE)
        cache = extra_buffer_cache;
    return cache;
}

void 
put_buffer_in_pool(void *buf, Uint32 buf_size)
{
    struct kmem_cache *cache=NULL;
    cache=get_cache(buf_size);
    if(cache == NULL){
       printk(KERN_CRIT "free cache NULL\n");
       return ; 
     }
    linux_cache_free(cache, (void *)buf);
}

Uint8 * 
get_buffer_from_pool(void *dev, Uint32 buf_size)
{
    struct kmem_cache *cache=NULL;
    cache=get_cache(buf_size);
    if(cache == NULL){
       printk(KERN_CRIT "Alloc cache NULL\n");
       return NULL; 
    }
    return linux_cache_alloc(cache);
}

/******************************************************** 
 * Function : init_buffer_pool
 *
 * Arguments    : cavium_general_config *
 * Return Value : Returns the status 0 (success) or
 *                1 (failure)
 * 
 * This function is used to intialize the buffer pool of 
 * the driver.The individual buffer pools are of size
 * 1k,2k,4k,8k,16k and 32k
 *
 ********************************************************/

Uint32
init_buffer_pool()
{
   cavium_dbgprint( "CAVIUM init_buffer_pool: called\n");
   
   MPRINTFLOW();
   extra_buffer_cache=linux_cache_init("__extra_pool", EXTRA_BUFFER_CHUNK_SIZE);
   if(extra_buffer_cache==NULL)
   {
      cavium_print( "PKP init_buffer_pool: failed to alloc extra\n");
      goto failed;
   }
   
   /* 32 kB buffers */
   huge_buffer_cache=linux_cache_init("__huge_pool", HUGE_BUFFER_CHUNK_SIZE);
   if(huge_buffer_cache==NULL)
   {
      cavium_print( "PKP init_buffer_pool: failed to alloc huge\n");
      goto failed;
   }

   /* 16 kB buffers */
   large_buffer_cache=linux_cache_init("__large_pool", LARGE_BUFFER_CHUNK_SIZE);
   if(large_buffer_cache==NULL)
   {
      cavium_print( "PKP init_buffer_pool: failed to alloc large\n");
      goto failed;
   }
   /* 8 kB buffers */
   medium_buffer_cache=linux_cache_init("__medium_pool", MEDIUM_BUFFER_CHUNK_SIZE);
   if(medium_buffer_cache==NULL)
   {
      cavium_print( "PKP init_buffer_pool: failed to alloc medium\n");
      goto failed;
   }

   /* 4 kB buffers */
   small_buffer_cache=linux_cache_init("__small_pool", SMALL_BUFFER_CHUNK_SIZE);
   if(small_buffer_cache==NULL)
   {
      cavium_print( "PKP init_buffer_pool: failed to alloc small\n");
      goto failed;
   }
   /*  2 kB buffers */
   tiny_buffer_cache=linux_cache_init("__tiny_pool", TINY_BUFFER_CHUNK_SIZE);
   if(tiny_buffer_cache==NULL)
   {
      cavium_print( "PKP init_buffer_pool: failed to alloc tiny\n");
      goto failed;
   }
  /*1K buffers */
   ex_tiny_buffer_cache=linux_cache_init("__ex_tiny_pool", EX_TINY_BUFFER_CHUNK_SIZE);
   if(ex_tiny_buffer_cache==NULL)
   {
      cavium_print( "PKP init_buffer_pool: failed to alloc ex_tiny\n");
      goto failed;
   }
   cavium_dbgprint("Returning from init_buffer_pool\n");
   return 0;
 
failed:
   free_buffer_pool();
   return 1;
}


/*************************************************** 
 * Function : free_buffer_pool
 *
 * Arguments       : void
 * Return Value    : Returns void 
 *
 * This function free the individual buffer pools 
 * of different sizes.
 *
 ***************************************************/
void 
free_buffer_pool(void)
{
   if(ex_tiny_buffer_cache){
        linux_cache_destroy(ex_tiny_buffer_cache);
        ex_tiny_buffer_cache=NULL;
    }
   if(tiny_buffer_cache){
        linux_cache_destroy(tiny_buffer_cache);
        tiny_buffer_cache=NULL;
    }
   if(small_buffer_cache){
        linux_cache_destroy(small_buffer_cache);
        small_buffer_cache=NULL;
    }
   if(medium_buffer_cache){
        linux_cache_destroy(medium_buffer_cache);
        medium_buffer_cache=NULL;
    }
   if(large_buffer_cache){
        linux_cache_destroy(large_buffer_cache);
        large_buffer_cache=NULL;
    }
   if(huge_buffer_cache){
        linux_cache_destroy(huge_buffer_cache);
        huge_buffer_cache=NULL;
    }
   if(extra_buffer_cache){
        linux_cache_destroy(extra_buffer_cache);
        extra_buffer_cache=NULL;
    }
}
