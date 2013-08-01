/* hw_lib.c */
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
#include "hw_lib.h"
#include "init_cfg.h"
#include "command_que.h"
#if defined(INTERRUPT_ON_COMP) || defined(INTERRUPT_COALESCING)
#include "interrupt.h"
#if defined(CONFIG_PCI_MSI)
extern int msi_enabled;
extern int free_interrupt(cavium_device *);
extern int setup_interrupt(cavium_device *);
#endif
#endif


int NITROX_MASK_COUNT=0;
Uint32 csrbase_a_offset=0x0000;
extern short maxcores;
extern int n3_vf_driver;
extern short ipsec,ssl;
#define FUS_REG_OFFSET 0x350
int reset_time=0;

void find_cfg_part_initialize(cavium_device *pkp_dev)
{

   Uint32 dval=0;
   int suffix=0;
   int cores=0;
   if(pkp_dev->device_id==NPX_DEVICE)
   {
        NITROX_MASK_COUNT = 1;
        read_PKP_register(pkp_dev,pkp_dev->csrbase_b+FUS_REG_OFFSET,&dval);
        pkp_dev->CORE_MASK_0=dval;      

        switch(dval)
        {
              case 0xff: cores=8;
                         suffix=20;
                         break;
              case 0x3f: cores=6;
                         suffix=15;
                         break;
              case 0x0f: cores=4;
                         suffix=10;
                         break;
              case 0x03: cores=2;
                         suffix=5;
                         break;
        }

       if(pkp_dev->px_flag==CN16XX)
       {
            if(cores==2)
            {
                cavium_print("part number=160%d\n",suffix);
            }
           else
           {
                 cavium_print("part number=16%d\n",suffix);
           }

       }
       else if(pkp_dev->px_flag==CN15XX)
       {
             if(cores==2)
             {
                cavium_print("part number=150%d\n",suffix);
             }
             else
             {
                cavium_print("part number=15%d\n",suffix);
             }

       }
       pkp_dev->max_cores=cores;
       cavium_print("total number of cores=%d \n",cores);
     }else if(pkp_dev->device_id == N3_DEVICE)
     {
          pkp_dev->max_cores=maxcores;
          if(!pkp_dev->max_cores){
             pkp_dev->max_cores=0;
             if(ssl>0 || ipsec>0){
               if(ssl>0)
                 pkp_dev->max_cores+=ssl;
               if(ipsec>0)
                 pkp_dev->max_cores+=ipsec;
             }else
                pkp_dev->max_cores=MAX_CORES_NITROX;
             
          }
         if(pkp_dev->max_cores>32){
          pkp_dev->CORE_MASK_0=get_coremask(32);
          pkp_dev->CORE_MASK_1=get_coremask(pkp_dev->max_cores-32);
         }else{
          pkp_dev->CORE_MASK_0=get_coremask(pkp_dev->max_cores);
          pkp_dev->CORE_MASK_1=0;
         }
          cavium_print("part number=CNN35XX has %d cores\n",pkp_dev->max_cores);
     }   
}

void
set_PCIX_split_transactions(cavium_device * pkp_dev)
{
   Uint32 dwval = 0;
    MPRINTFLOW();
   read_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A + COMMAND_STATUS), &dwval);
   if (dwval & 0x1000) 
   {
      read_PCI_register(pkp_dev, PCIX_SPLIT_TRANSACTION, &dwval);
      dwval=dwval & ~SPLIT_TRANSACTION_MASK;
      write_PCI_register(pkp_dev, PCIX_SPLIT_TRANSACTION, dwval);
   }
   return;
}

void
set_PCI_cache_line(cavium_device * pkp_dev)
{
    MPRINTFLOW();
   write_PCI_register(pkp_dev, PCI_CACHE_LINE, 0x02);
}




Uint32
get_exec_units_part(cavium_device * pkp_dev)
{
   Uint32 uen=0,i,core_count,unit;
   int max_cores=0;
    MPRINTFLOW();
   uen=0;
   core_count=0;
   unit=0;

   if(pkp_dev->device_id == NPX_DEVICE)
      max_cores=MAX_CORES_NITROX;
   else if(pkp_dev->device_id == N3_DEVICE)
      max_cores=pkp_dev->max_cores;
   for(i=0;i<max_cores; i++)
   {
       unit = cavium_pow(2,i);
       if(unit)
       {
         uen |= unit;
         core_count++;
         if(core_count == pkp_dev->exec_units) {
   		cavium_dbgprint("%s(): %d: uen: 0x%x\n", __func__, __LINE__, pkp_dev->exec_units);
            return uen;
      }
    }
    }
   cavium_dbgprint("%s(): %d: uen: 0x%x\n", __func__, __LINE__, pkp_dev->exec_units);
   return uen;
}/*get_exec_units_part*/

/* bit mask should have only one bit set */
Uint32
get_unit_id(Uint32 bit_mask)
{
   Uint32 i;
 
    MPRINTFLOW();
   for(i=0; i<MAX_CORES_NITROX; i++)
   {
     if(((bit_mask >> i) & 0x00000001))
       break;
   }

   return i;

}

int 
check_core_mask(cavium_device *pkp_dev, Uint32 uen_mask)
{

    MPRINTFLOW();
   if(uen_mask == pkp_dev->CORE_MASK_0)
      return 0;

   else if(uen_mask == pkp_dev->CORE_MASK_1)
      return 0;
   
   else if(uen_mask == pkp_dev->CORE_MASK_2)
      return 0;

   else
   {
      cavium_print("Final core mask %08x is not one of following:\n", uen_mask);
      cavium_print("(1) %08x\n", pkp_dev->CORE_MASK_0);
      cavium_print("(2) %08x\n", pkp_dev->CORE_MASK_1);
      cavium_print("(3) %08x\n", pkp_dev->CORE_MASK_2);
      return 1;
   }
}/* check_core_mask */



void 
set_soft_reset(cavium_device * pkp_dev)
{
   Uint32 dwval;
    MPRINTFLOW();
   dwval = 0;
   if(pkp_dev->device_id == NPX_DEVICE){
    read_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A + COMMAND_STATUS), &dwval);
    dwval = dwval | 0x00000020;
    write_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A + COMMAND_STATUS), dwval);
  }else if(pkp_dev->device_id == N3_DEVICE)
  {
    read_PKP_register(pkp_dev, (pkp_dev->CSRBASE_A + N3_CMD_REG),&dwval);
    dwval=dwval|0x00000020;
    write_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A + N3_CMD_REG), dwval);
   /* N3 requires 10ms Delay */
    cavium_udelay(10000);
  }

}/*void set_soft_reset(void)*/


int 
count_set_bits(Uint32 value, int bit_count)
{
   int i, count;
   Uint32 dummy;
 
   count = 0;
   dummy = value;
 
   for(i=0; i<bit_count; i++)
   {
     if(((dummy >> i) & 0x00000001))
       count++;
   }

   return count;
}

/* returns the value of x raised by y*/
Uint32 
cavium_pow(Uint32 x, Uint32 y)
{
   Uint32 i;
   Uint32 ret=x;
   if(y == 0)
      return 1;
   for(i=0; i<y-1; i++)
      ret = ret*x;

   return ret;
}

Uint32  
get_first_available_core(Uint32 max, Uint32 mask)
{
   Uint32 i;

    MPRINTFLOW();
    for(i=0; i < max; i++) 
    {
       if(((mask >> i) & 0x00000001))
                break;
    } 
 
    return cavium_pow(2, i);
}



int do_soft_reset(cavium_device *pkp_dev)
{
   Uint32 i;
   Uint32 j;
    MPRINTFLOW();
#ifdef CONFIG_PCI_MSI
#if defined(INTERRUPT_ON_COMP) || defined(INTERRUPT_COALESCING)
          if(msi_enabled)
              free_interrupt(pkp_dev);
#endif
#endif
   reset_time=1;
   set_soft_reset(pkp_dev);
   cavium_udelay(1000); /* Need a 1ms delay here before we proceed. */
   if(pkp_dev->device_id == N3_DEVICE && !n3_vf_driver){
      if (fix_phy_calibration(pkp_dev))
	 return 1; // Calibration failed
      if (tune_serdes(pkp_dev))
	 return 1; // Serdes Tuning failed 
      cavium_load_credits(pkp_dev);
      if(cavium_check_bist(pkp_dev))
          return 1;
   }
   for (i = 0; i < pkp_dev->max_queues; i++) 
   {
      cavium_spin_lock_destroy(&(pkp_dev->command_queue_lock[i]));
   }
   for (i = 0; i < pkp_dev->max_queues; i++) 
   {
      cleanup_command_queue(pkp_dev, i);
       if(pkp_dev->pending_queue[i].cmd_queue)
           kfree(pkp_dev->pending_queue[i].cmd_queue);
       pkp_dev->pending_queue[i].cmd_queue=NULL;
       cavium_spin_lock_destroy(&(pkp_dev->pending_queue[i].pending_lock));
     
   }
   for (i = 0; i < pkp_dev->max_queues; i++) 
   {
      cavium_spin_lock_init(&(pkp_dev->command_queue_lock[i]));
   }
   for (i = 0; i < pkp_dev->max_queues; i++) 
   {
      init_command_queue(pkp_dev, i);
      pkp_dev->pending_queue[i].cmd_queue=(CMD_DATA *)kmalloc(sizeof(CMD_DATA)*MAX_PENDING_QUEUE_SIZE,GFP_ATOMIC);
      if(pkp_dev->pending_queue[i].cmd_queue == NULL)
      {
         cavium_error("init_command_queue failed\n");
         goto error;
      }
      pkp_dev->pending_queue[i].queue_size=MAX_PENDING_QUEUE_SIZE;
      cavium_spin_lock_init(&(pkp_dev->pending_queue[i].pending_lock));
      pkp_dev->pending_queue[i].queue_front=0;
      pkp_dev->pending_queue[i].queue_rear=0;
      memset(pkp_dev->pending_queue[i].cmd_queue,0x0, sizeof(CMD_DATA)*MAX_PENDING_QUEUE_SIZE);
      for(j=0;j<MAX_PENDING_QUEUE_SIZE;j++)
      {
         (pkp_dev->pending_queue[i].cmd_queue)[j].free=1;
      }
   }
#if defined(INTERRUPT_ON_COMP) || defined(INTERRUPT_COALESCING)
if(pkp_dev->device_id == NPX_DEVICE)
   enable_all_interrupts_px(pkp_dev);
else if(pkp_dev->device_id == N3_DEVICE)
   enable_all_interrupts_n3(pkp_dev);
else
   printk(KERN_CRIT "Unexpected Device\n");
   
#endif

   if(pkp_init_board(pkp_dev))
      goto error;

   if(do_init(pkp_dev))
      goto error;
#ifdef CONFIG_PCI_MSI
#if defined(INTERRUPT_ON_COMP) || defined(INTERRUPT_COALESCING)
   if(pkp_dev->device_id==NPX_DEVICE || pkp_dev->device_id == N3_DEVICE)   
      if(msi_enabled)
          setup_interrupt(pkp_dev);

#endif
#endif
   reset_time=0;
   return 0;
error:
   for (i = 0; i < pkp_dev->max_queues; i++)
   {
      cleanup_command_queue(pkp_dev, i);
       if(pkp_dev->pending_queue[i].cmd_queue)
           kfree(pkp_dev->pending_queue[i].cmd_queue);
       pkp_dev->pending_queue[i].cmd_queue=NULL;
       cavium_spin_lock_destroy(&(pkp_dev->pending_queue[i].pending_lock));
   } 
   return 1;
}

inline Uint64 get_core_mask(cavium_device *pdev, int ucode_idx)
{
   Uint64 core_mask = 0ULL;
   Uint8 id = pdev->microcode[ucode_idx].core_id;
   MPRINTFLOW();
   while(id != (Uint8)-1)
   {
      core_mask |= ((Uint64)1) << id;
      id = pdev->cores[id].next_id;
   }
   return core_mask;
} 
/*
 * $Id: hw_lib.c,v 1.24 2009/10/22 10:02:30 kkiran Exp $
 * $Log: hw_lib.c,v $
 * Revision 1.24  2009/10/22 10:02:30  kkiran
 *  Cavium_udelay(20) added after writing the PKP register.
 *
 * Revision 1.23  2009/09/09 11:26:19  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.22  2008/12/22 05:42:10  jrana
 *  COUNTERS and INTERRUPT COALEASCING ADDED
 *
 * Revision 1.21  2008/12/16 12:04:42  jsrikanth
 * Added Common driver and Multi-Card Changes for FreeBSD
 *
 * Revision 1.20  2008/09/30 13:15:17  jsrikanth
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
 * Revision 1.19  2008/07/28 11:42:05  aramesh
 * done proper indendation.
 *
 * Revision 1.18  2008/07/18 05:55:32  aramesh
 * deleted pci_find_capability.
 *
 * Revision 1.17  2008/07/03 05:04:37  aramesh
 * deleted unwanted comments.
 *
 * Revision 1.16  2008/07/02 12:35:26  aramesh
 * deleted part number and corresponding flags.
 *
 * Revision 1.15  2008/04/04 16:21:09  dpatel
 * fixed printf which caused compile error for CN505.
 *
 * Revision 1.14  2008/03/11 08:54:47  kchunduri
 * --Use exact part number for CN15XX family.
 *
 * Revision 1.13  2008/02/14 05:37:35  kchunduri
 * --remove CN1600 dependency.
 *
 * Revision 1.12  2008/02/12 13:04:39  kchunduri
 * -- Disable core mask check for CN16XX family.
 *
 * Revision 1.11  2007/11/05 08:52:46  tghoriparti
 * MSI support added for CN1600
 *
 * Revision 1.10  2007/11/02 09:40:37  tghoriparti
 * After setting the reset bit of COMMAND STATUS register, enable_all_interrupts must be called.
 *
 * Revision 1.9  2007/06/11 07:48:38  tghoriparti
 * Fetching exec units directly by reading the register at 0x350 instead of using debug register in case of NITROX_PX
 *
 * Revision 1.8  2007/04/04 21:50:25  panicker
 * * Added support for CN1600
 * * Masks renamed as CNPX_* since both parts use the same mask
 *
 * Revision 1.7  2007/03/08 20:43:33  panicker
 * * NPLUS mode changes. pre-release
 * * NitroxPX now supports N1-style NPLUS operation.
 * * Native PX mode PLUS operations are enabled only if PX_PLUS flag is enabled
 *
 * Revision 1.6  2007/03/06 03:10:22  panicker
 * * PX will use the same core id lookup mechanism as N1.
 * * get_core_mask() does not require PX specific path
 *
 * Revision 1.5  2007/02/21 23:30:00  panicker
 * * soft reset needs a 1ms delay
 *
 * Revision 1.4  2007/02/20 22:53:24  panicker
 * * queue_base in setup_request_queues() is Uint64 now.
 *
 * Revision 1.3  2007/02/02 02:31:01  panicker
 * * enable_request_unit()
 *   - swap bits are set for PX
 *   - IQM enable bits are different for PX
 * * Core enable bits are different for PX
 * * queue base address was assumed to be 32-bits. Fixed now.
 *
 * Revision 1.2  2007/01/11 02:00:07  panicker
 * * get_core_mask() - existing code under !(NITROX_PX); for PX, the core is
 *   returned from the microcode core_mask field.
 * * get_core_pair() is used when !(NITROX_PX).
 *
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.26  2006/10/30 12:06:00  ksnaren
 * Fixed warnings for CN1005
 *
 * Revision 1.25  2006/05/16 09:33:07  kchunduri
 * --support for Dynamic DMA mapping instead of virt_to_phys
 *
 * Revision 1.24  2005/12/13 09:43:49  pravin
 * - Fixed Nplus related compilation issues on Linux 2.4 kernels.
 *
 * Revision 1.23  2005/12/07 04:50:59  kanantha
 * modified to support both 32 and 64 bit versions
 *
 * Revision 1.22  2005/11/17 13:31:09  kanantha
 * Updating with the 64 bit modifications, with proper matching of data types
 *
 * Revision 1.21  2005/10/24 06:52:58  kanantha
 * - Fixed RHEL4 warnings
 *
 * Revision 1.20  2005/10/13 09:24:02  ksnaren
 * fixed compile warnings
 *
 * Revision 1.19  2005/09/28 15:50:26  ksadasivuni
 * - Merging FreeBSD 6.0 AMD64 Release with CVS Head
 * - Now context pointer given to user space applications is physical pointer.
 *   So there is no need to do cavium_vtophys() of context pointer.
 *
 * Revision 1.18  2005/09/06 14:38:57  ksadasivuni
 * - Some cleanup error fixing and spin_lock_destroy functionality added to osi.
 *   spin_lock_destroy was necessary because of FreeBSD 6.0.
 *
 * Revision 1.17  2005/09/06 07:08:22  ksadasivuni
 * - Merging FreeBSD 4.11 Release with CVS Head
 *
 * Revision 1.16  2005/08/31 18:10:30  bimran
 * Fixed several warnings.
 * Fixed the corerct use of ALIGNMENT and related macros.
 *
 * Revision 1.15  2005/06/13 06:35:42  rkumar
 * Changed copyright
 *
 * Revision 1.14  2005/05/20 14:34:05  rkumar
 * Merging CVS head from india
 *
 * Revision 1.13  2005/02/04 00:12:27  tsingh
 * added 1330 and 1320
 *
 * Revision 1.12  2005/02/01 04:11:07  bimran
 * copyright fix
 *
 * Revision 1.11  2005/01/28 22:18:06  tsingh
 * Added support for HT part numbers.
 *
 * Revision 1.10  2005/01/26 20:34:56  bimran
 * Added NPLUS specific functions to check for available core pairs for Modexp operation.
 *
 * Revision 1.9  2004/10/06 19:31:54  tsingh
 * fixed some potential issues
 *
 * Revision 1.8  2004/06/23 20:08:38  bimran
 * compiler warnings on NetBSD.
 *
 * Revision 1.6  2004/05/10 21:32:26  bimran
 * query_ddr_sram is only called for supporting part numbers.
 *
 * Revision 1.5  2004/05/02 19:44:29  bimran
 * Added Copyright notice.
 *
 * Revision 1.4  2004/04/26 19:04:55  bimran
 * Added 505 support.
 *
 * Revision 1.3  2004/04/21 19:18:58  bimran
 * NPLUS support.
 *
 * Revision 1.2  2004/04/20 02:25:12  bimran
 * Fixed check_dram to use context_max passed in cavium_init() instead of defining its own DRAM_MAX macro.
 *
 * Revision 1.1  2004/04/15 22:40:49  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

