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
void 
enable_request_unit_px(cavium_device * pkp_dev)
{
   Uint32 dwval;

   MPRINTFLOW();
       /* BAR0:COMMAND[Bit 25] has special meaning for PX.
        * At reset it is 0, which leads to the IQ's being read in a round-robin
        * fashion. All previous parts gave IQ0 the highest priority. To get this
        * behavior, bit 25 should be set to 1.
        */
    dwval = 0;
    read_PKP_register(pkp_dev, (pkp_dev->CSRBASE_A + COMMAND_STATUS), &dwval);
    dwval |= 0x2000005; /*** SETTING SWAP AS WELL HERE */
    write_PKP_register(pkp_dev, (pkp_dev->CSRBASE_A + COMMAND_STATUS), dwval);
    dwval = 0; 
    read_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A + UNIT_ENABLE), &dwval);
 
    cavium_udelay(10);
    dwval = dwval | 0xf0000000;
    write_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A + UNIT_ENABLE), dwval);
}


void 
disable_request_unit_px(cavium_device *pkp_dev)
{
   Uint32 dwval;

   MPRINTFLOW();
   dwval = 0; 
   read_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A + UNIT_ENABLE), &dwval);

   cavium_udelay(10); 
   dwval = dwval & 0x0fffffff;
   write_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A + UNIT_ENABLE), dwval);
}

void
disable_exec_units_from_mask_px(cavium_device *pkp_dev, Uint64 val)
{
   Uint32 dwval = 0;
   Uint32 mask=(Uint32)val;

   MPRINTFLOW();
   read_PKP_register(pkp_dev, (pkp_dev->CSRBASE_A + UNIT_ENABLE), &dwval);

   cavium_udelay(10);
   dwval = dwval & (~mask);

   write_PKP_register(pkp_dev, (pkp_dev->CSRBASE_A + UNIT_ENABLE), dwval);
}


void 
disable_all_exec_units_px(cavium_device * pkp_dev)
{
   Uint32 dwval;
   MPRINTFLOW();
   dwval = 0;
   read_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A + UNIT_ENABLE), &dwval);
   cavium_udelay(10);
   dwval = dwval & 0xf0000000;
   write_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A + UNIT_ENABLE), dwval);
} 

void
enable_exec_units_px(cavium_device * pkp_dev)
{
   Uint32 dwval=0;

   MPRINTFLOW();
   read_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A+UNIT_ENABLE), &dwval);
   dwval = (dwval & 0xf0000000) | pkp_dev->uen;
   cavium_udelay(10);
   write_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A+UNIT_ENABLE), dwval);
   cavium_udelay(20);
}

void
enable_exec_units_from_mask_px(cavium_device * pkp_dev, Uint64 val)
{
   Uint32 dwval=0;
   Uint32 mask=(Uint32)val;
   MPRINTFLOW();
   read_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A+UNIT_ENABLE), &dwval);
   cavium_udelay(10);

   cavium_dbgprint("enable_exec_units_from_mask: Current: 0x%x Coremask will be 0x%x\n",
           dwval, (dwval|mask));
   dwval |= mask;
   write_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A+UNIT_ENABLE), dwval);
}

void 
setup_request_queues_px(cavium_device * pkp_dev)
{
    volatile Uint64 queue_base=0;
    volatile Uint32 length=0;
   int i;

    MPRINTFLOW();
    length = pkp_dev->command_queue_max;
 
 /* setup Request Queues */
    for(i = 0; i < pkp_dev->max_queues; i++) 
    {
     queue_base = (Uint64) pkp_dev->command_queue_bus_addr[i];
       cavium_dbgprint ("queue_base = 0x%llx\n", CAST64(queue_base));
       cavium_dbgprint ("queue_length = %x\n", length);
       cavium_udelay(1000);
       write_PKP_register(pkp_dev,(pkp_dev->CSRBASE_B+REQ0_BASE_LOW +0x20*i),
               (queue_base & 0xffffffff));
       cavium_udelay(1000);
       write_PKP_register(pkp_dev,(pkp_dev->CSRBASE_B+REQ0_BASE_HIGH + 0x20*i), 
               ((queue_base & 0xffffffff00000000ULL) >> 32));
       cavium_udelay(1000);
       write_PKP_register(pkp_dev,(pkp_dev->CSRBASE_B+REQ0_SIZE +0x20*i), length);
       cavium_udelay(1000);
    }
}


void 
enable_data_swap_px(cavium_device * pkp_dev)
{
   Uint32 dwval=0;
    MPRINTFLOW();
    read_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A + COMMAND_STATUS), &dwval);
    cavium_udelay(10); 

   dwval = dwval | 0x5;
   write_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A + COMMAND_STATUS), dwval);
}

void
enable_rnd_entropy_px(cavium_device *pkp_dev)
{
   Uint32 dwval=0;
    MPRINTFLOW();
     read_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A + COMMAND_STATUS), &dwval);
 
     cavium_udelay(10); 

     dwval = dwval | 0x200;
     write_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A + COMMAND_STATUS), dwval);
}


Uint32 
get_exec_units_px(cavium_device * pkp_dev)
{
   Uint32 dwval = 0;
   Uint32 ret = 0;

    MPRINTFLOW();
   /* now determine how many exec units are present */
   read_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A + 0x350), &dwval);
   pkp_dev->uen = dwval;
   ret = count_set_bits(dwval, 8);
   return ret;
}/*int get_exec_units(void)*/



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

