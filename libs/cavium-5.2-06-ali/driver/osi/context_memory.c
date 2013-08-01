/* context_memory.c */
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
#include "context_memory.h"


#include "init_cfg.h"
#include "buffer_pool.h"

/* These should be in sync with CtxType enum */
static
Uint32 ctx_mem_sizes[] = 
{
   SSL_CONTEXT_SIZE,
   IPSEC_CONTEXT_SIZE,
   ECC_P256_CONTEXT_SIZE,
   ECC_P384_CONTEXT_SIZE
};

/* context memory */
extern int dev_count;
volatile Uint32 allocated_context_count = 0;

/*
 * Initialize context buffers
 */
int 
init_context(cavium_device *pkp_dev)
{
  cavium_dbgprint("ctx init simulated (i.e, using buffer pool)\n");
 return 0;
}/*init_context*/

Uint64
alloc_context(cavium_device *pkp_dev, ContextType c)
{
   Uint8 *ptr = NULL;
   Uint8 *vptr = NULL;
   struct ctx_addr *caddr=NULL;
   MPRINTFLOW();
   
   if(c > CONTEXT_ECC_P384)
   {
     cavium_error("request for invalid ctxtype=%d\n",(int)c);
     return 0;
   }

   ptr = get_buffer_from_pool(pkp_dev,2048+sizeof(struct ctx_addr) + ctx_mem_sizes[(int)c]);
   if(!ptr) 
   {
     cavium_dbgprint("ctx type=%d get_buffer_from_pool failed\n",(int)c);
     return 0;
   }

   vptr =(Uint8 *)CAST_FRM_X_PTR((CAST_TO_X_PTR(ptr + 2048)) & ~(0x7FF));
   caddr = (struct ctx_addr *)vptr;
   memset(vptr ,0x0 ,sizeof(struct ctx_addr) + ctx_mem_sizes[(int)c]);
   caddr->virt_addr =(Uint8 *)CAST_FRM_X_PTR((CAST_TO_X_PTR(vptr + sizeof(struct ctx_addr)+ALIGNMENT)) & ALIGNMENT_MASK);
   caddr->phy_addr = cavium_map_kernel_buffer(pkp_dev,caddr->virt_addr,
                                               ctx_mem_sizes[(int)c], 
                                               CAVIUM_PCI_DMA_BIDIRECTIONAL);
   caddr->virt_addr=ptr;
    caddr->dev=pkp_dev;
   return CAST_TO_X_PTR(vptr);

}
   
#ifdef CAVIUM_RESOURCE_CHECK
int
insert_ctx_entry(cavium_device *pdev,struct cavium_list_head *ctx_head, ContextType c, Uint64 addr)
{
   struct CTX_ENTRY *entry;
   
   MPRINTFLOW();
   entry = cavium_malloc(sizeof(struct CTX_ENTRY), NULL);
   if (entry == NULL) {
      cavium_error("Insert-ctx-entry: Not enough memory\n");
      return -1;
   }

   entry->ctx = addr;
   entry->ctx_type = c;
   entry->pkp_dev = pdev;

   cavium_list_add_tail(&entry->list, ctx_head);   
   
   return 0;
}
#endif

void 
dealloc_context(cavium_device *pkp_dev, ContextType c, Uint64 addr)
{
    int ctx_size=0;
    cavium_dmaaddr ctx_addr;
    Uint8 *vaddr=NULL;
    struct ctx_addr *caddr=NULL;
    MPRINTFLOW();

    if (c == CONTEXT_IPSEC)  
         ctx_size=IPSEC_CONTEXT_SIZE;
    else
         ctx_size=SSL_CONTEXT_SIZE;
    caddr = ((struct ctx_addr *)(ptrlong)addr);
    if(!caddr)
    {
      printk(KERN_CRIT "Invalid context \n");
      return;
    }
     vaddr=caddr->virt_addr;
     ctx_addr=caddr->phy_addr;
    if(ctx_addr)
    {
      cavium_unmap_kernel_buffer(caddr->dev,ctx_addr,ctx_size,
                          CAVIUM_PCI_DMA_BIDIRECTIONAL);
      put_buffer_in_pool((Uint8*)vaddr,ctx_size + sizeof(struct ctx_addr)+2048);
    }
}
/*
 * Free memory 
 */
int 
cleanup_context(cavium_device *pkp_dev)
{
   cavium_dbgprint("ctx cleanup simulated (i.e, using buffer pool)\n");
   return 0;
}/*cleanup_context*/

#ifdef DUMP_FAILING_REQUESTS
Uint8 *
find_host_ctx(cavium_device *pkp_dev, Uint64 ctx_addr)
{
    Uint8 *ret = NULL;

    if (pkp_dev->dram_present || (!ctx_addr))
       return ret;

    ret = cavium_phystov(ctx_addr);
    return ret;
}
#endif

/*
 * $Id: context_memory.c,v 1.11 2011/02/07 09:58:33 sarora Exp $
 * $Log: context_memory.c,v $
 * Revision 1.11  2011/02/07 09:58:33  sarora
 *  - T710 bug fix related changes
 *
 * Revision 1.10  2011/02/02 12:49:01  sarora
 *  - Fixed driver reload crash bug for T710 machine
 *
 * Revision 1.9  2008/09/30 13:15:17  jsrikanth
 * PX-4X [Multicard] support for IPsec :
 *      -  Round-robin scheduling for selecting a device
 *         implemented within IPSec APIs.
 *      -  All Lists [Pending/Direct/SG/CompletionDMA]
 *         moved to device structure.
 *      -  A single buffer pool manager for all devices.
 *         Interrupt handler now checks for PCI Error register as well.
 *         Proc Entry bug fixes when dumping more than a single page.
 *         DUMP_FAILING_REQUESTS pre-processor define added to dump
 *         out all failing requests.
 * Minor modifications of removing all tabs to spaces.
 *
 * Revision 1.8  2008/02/22 10:20:13  aramesh
 * N1_SANITY is set always.
 *
 * Revision 1.7  2007/12/07 05:33:37  ksadasivuni
 * ptr should be freed not ptr-8 to buffer pool
 *
 * Revision 1.6  2007/12/07 05:24:18  ksadasivuni
 * 1.  changed context memory to use buffer pool as px doesn't have DDR
 * 2.  PX_ECC_FreeContext now takes cid argument
 *
 * Revision 1.5  2007/11/19 11:11:55  lpathy
 * ported to 64 bit windows.
 *
 * Revision 1.4  2007/10/18 09:35:09  lpathy
 * Added windows support.
 *
 * Revision 1.3  2007/09/10 10:56:18  kchunduri
 * --Maintain Context and KeyMemory resources per device.
 *
 * Revision 1.2  2007/06/11 13:41:07  tghoriparti
 * cavium_mmap_kernel_buffers return values handled properly when failed.
 *
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.24  2006/11/13 14:25:45  kchunduri
 * 'allocated_context_count' locked while updating.
 *
 * Revision 1.23  2006/05/16 09:32:28  kchunduri
 * --support for Dynamic DMA mapping instead of virt_to_phys
 *
 * Revision 1.22  2006/01/30 11:08:49  sgadam
 * - check in corrected
 *
 * Revision 1.21  2006/01/30 10:55:57  sgadam
 *  - ipsec and ssl chunk counts moved to device structure
 *
 * Revision 1.20  2006/01/30 07:13:48  sgadam
 * - ipsec context new put index added
 *
 * Revision 1.19  2006/01/24 07:52:31  pyelgar
 *    - For N1 with DDR fixed the context freeing in cleanup_command.
 *      For freebsd changed the interrupt level to splnet.
 *
 * Revision 1.18  2006/01/19 09:48:08  sgadam
 * - IPsec 2.6.11 changes
 *
 * Revision 1.17  2005/11/17 13:31:09  kanantha
 * Updating with the 64 bit modifications, with proper matching of data types
 *
 * Revision 1.16  2005/10/24 06:51:59  kanantha
 * - Fixed RHEL4 warnings
 *
 * Revision 1.15  2005/10/13 09:21:59  ksnaren
 * fixed compile errors for windows xp
 *
 * Revision 1.14  2005/09/28 15:50:26  ksadasivuni
 * - Merging FreeBSD 6.0 AMD64 Release with CVS Head
 * - Now context pointer given to user space applications is physical pointer.
 *   So there is no need to do cavium_vtophys() of context pointer.
 *
 * Revision 1.13  2005/09/06 14:38:57  ksadasivuni
 * - Some cleanup error fixing and spin_lock_destroy functionality added to osi.
 *   spin_lock_destroy was necessary because of FreeBSD 6.0.
 *
 * Revision 1.12  2005/08/31 18:10:30  bimran
 * Fixed several warnings.
 * Fixed the corerct use of ALIGNMENT and related macros.
 *
 * Revision 1.11  2005/07/17 04:35:09  sgadam
 * 8 bytes alignment issue on linux-2.6.2 is fixed. README and Makefile in
 * apps/cavium_engine updated
 *
 * Revision 1.10  2005/06/13 06:35:42  rkumar
 * Changed copyright
 *
 * Revision 1.9  2005/05/20 14:34:05  rkumar
 * Merging CVS head from india
 *
 * Revision 1.8  2005/02/01 04:11:07  bimran
 * copyright fix
 *
 * Revision 1.7  2004/06/03 21:22:56  bimran
 * included cavium_list.h
 * fixed list* calls to use cavium_list
 *
 * Revision 1.6  2004/05/04 20:48:34  bimran
 * Fixed RESOURCE_CHECK.
 *
 * Revision 1.5  2004/05/02 19:44:29  bimran
 * Added Copyright notice.
 *
 * Revision 1.4  2004/04/30 00:00:33  bimran
 * Removed semaphoers from context memory in favour of just counts and a lock.
 *
 * Revision 1.3  2004/04/21 21:21:04  bimran
 * statis and free lists were using DMA memory for no reason. Changed the memory allocation to virtual.
 *
 * Revision 1.2  2004/04/20 02:23:17  bimran
 * Made code more generic. Divided context memory into two portions, one for Ipsec and One for SSL.
 * Fixed  bug where DDR was present and index was not pushed in free list.
 *
 * Revision 1.1  2004/04/15 22:40:48  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

