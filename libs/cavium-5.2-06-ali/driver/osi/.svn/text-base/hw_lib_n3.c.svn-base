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
extern int boot_time;
extern int n3_vf_driver;
/*
 * Only for N3
 * change_exec_mask
 * mask : mask of all 64 cores
 * en : 0 - disable exec mask 
 * en : 1 - enable exec mask
 * en : 2 - set exec mask
 * When in disable mode, if mask_lo is 0x3 and mask_hi 0x3 ---> cores 0,1,16,17 will removed from Queues, rest untouched
 * When in enable mode, if mask_lo is 0x3 and mask_hi 0x3 --> cores 0,1,16,17 will be enabled for all queues, rest untouched
 * When in set mode, if mask_lo is 0x3 and mask_hi 0x3 --> only cores 0,1,16,17 will be enabled for all queues, rest disabled.
 */
void change_exec_mask_n3(cavium_device *pkp_dev, Uint64 mask, Uint8 en)
{
   Uint32 dwval, mask_lo = (mask<<32)>>32, mask_hi = (mask>>32);
   int i;
   for(i=0;i<MAX_N3_QUEUES;i++)
   {
     if(en != 2)
     read_PKP_register(pkp_dev, pkp_dev->CSRBASE_A + (N3_IQM0_EXEC_MSK_LO+(i<<8)), &dwval);
     if(en == 1)
        dwval |= mask_lo;
     else if (en == 2)
	dwval = mask_lo;
     else
	dwval &= ~mask_lo;    
     write_PKP_register(pkp_dev,  pkp_dev->CSRBASE_A + (N3_IQM0_EXEC_MSK_LO+(i<<8)), dwval);
     
     if(en != 2)
     read_PKP_register(pkp_dev, pkp_dev->CSRBASE_A + (N3_IQM0_EXEC_MSK_HI+(i<<8)), &dwval);
 
     if(en == 1)
	dwval |= mask_hi;
     else if (en== 2)
	dwval = mask_hi;
     else
	dwval &= ~mask_hi;
     write_PKP_register(pkp_dev, pkp_dev->CSRBASE_A + (N3_IQM0_EXEC_MSK_HI+(i<<8)), dwval);
   }
}

#define SPIN_FOR_ACK(ack_value) \
({				\
	Uint32 dwval;		\
	do { 			\
		read_PKP_register(cvmdev, serdes_status_addr, &dwval);\
		while ((dwval >> 31) != ack_value) { \
			read_PKP_register(cvmdev, serdes_status_addr, &dwval);\
		} \
	} while(0);		\
})

// Clear command CSR and wait for ACK to drop
#define CLEAR_CMD() 	\
({		    	\
	do {		\
		write_PKP_register(cvmdev, serdes_config_addr, 0); \
		SPIN_FOR_ACK(0); \
	} while(0);		\
})

// Write a valid command and wait for ACK to go high
#define WRITE_CMD(v) 	\
({			\
	do {		\
		write_PKP_register(cvmdev, serdes_config_addr, v);\
		SPIN_FOR_ACK(1);\
	} while(0);\
})

//Issue an entire CR bus cycle
#define DO_CMD(v) \
({		  \
	do {	  \
		WRITE_CMD(v);\
		CLEAR_CMD();\
	} while(0);\
})

static void write_pci_phy_cr(cavium_device *cvmdev, int phy, unsigned int addr, uint16_t value)
{
	char *serdes_config_addr = cvmdev->CSRBASE_A + 0x140 + phy * 0x8;
	char *serdes_status_addr = cvmdev->CSRBASE_A + 0x160 + phy * 0x8;
	uint32_t config_v;

	//Clear ACK if present
	CLEAR_CMD();

	//Capture address
	config_v = (1 << 16) | addr;
	DO_CMD(config_v);

	//Capture Data
	config_v = (1 << 17) | value;
	DO_CMD(config_v);

	//Issue Write
	config_v = (1 << 19);
	DO_CMD(config_v);
}

static uint16_t read_pci_phy_cr(cavium_device *cvmdev, int phy, unsigned int addr)
{
	char *serdes_config_addr = cvmdev->CSRBASE_A + 0x140 + phy * 0x8;
	char *serdes_status_addr = cvmdev->CSRBASE_A + 0x160 + phy * 0x8;
	uint32_t config_v;
	Uint32 dwval;

	//Clear ACK if present
	CLEAR_CMD();

	//Capture Address
	config_v = (1 << 16) | addr;
	DO_CMD(config_v);

	//Issue Read
	config_v = (1 << 18);
	DO_CMD(config_v);

	read_PKP_register(cvmdev, serdes_status_addr, &dwval);
	dwval &= 0xFFFF;
	return dwval;
}

/* Fix Nitrox3 PHY Calibration. Run on every device probe, after MMIO BARs are setup.
 * Can be run before credits are initialixed, since it only accesses the HSI block.
 */
int fix_phy_calibration(cavium_device *cvmdev)
{
	int phy;
	uint16_t status;
	uint16_t override;
	bool all_clear = true;

	for (phy = 0; phy < 4; phy++) {
		// Read SUP_DIG_MPLL_ASIC_IN
		status = read_pci_phy_cr(cvmdev, phy, 0xB);
		// Resistor call is done if bits 10 and 11 are clear
		all_clear = all_clear && ((status & 0xc00) == 0);
	}

	if (!all_clear) {
		cavium_print("Applying n3k PHY RX calibration workaround: \n");
		status   = read_pci_phy_cr(cvmdev, 3, 0xB);
		override = status & 0x3ff;

		/* Set Bit 11, 12 and 13 of override: (ACK, WORD_CLK_EN and EN
 		 * -- note: Rev 2.2 of Synopsis datasheet is WRONG. They are missing
 		 * WORD_CLK_EN and put EN at bit 12 instead)
 		 */
		override |= 0x3800;

		/* Override settins of phy 3, then clear the override enable bit. The 
 		 * other PHYs should fall in line.
 		 */
		write_pci_phy_cr(cvmdev, 3, 7, override);
		override &= ~(0x2000);
		write_pci_phy_cr(cvmdev, 3, 7, override);

		all_clear = true;
		for (phy = 0; phy < 4; phy++) {
			//Read SUP_DIG_MPLL_ASIC_IN
			status = read_pci_phy_cr(cvmdev, phy, 0xB);
			//Resistor call is done if bits 10 and 11 are clear
			all_clear = all_clear && ((status & 0xc00) == 0);
		}

		if (all_clear)
			return 0; // Success
		else
			return 1;
	} else
		return 0; //Success
}

int tune_serdes(cavium_device *cvmdev)
{
  Uint32 dwval=0;
  /* Read SERDES_TUNING register */
  read_PKP_register(cvmdev, cvmdev->CSRBASE_A + N3_SERDES_TUNING, &dwval);
  if (dwval == 0x458CC58) {
  	cavium_print("SERDES_TUNING register value is already set: 0x%x\n", dwval);
  	return 0;
  } else if (dwval == 0x5DF1CDB) {
  	write_PKP_register(cvmdev, cvmdev->CSRBASE_A + N3_SERDES_TUNING, 0x678CC70);
  } else if (dwval == 0x7FF1CF3) {
  	write_PKP_register(cvmdev, cvmdev->CSRBASE_A + N3_SERDES_TUNING, 0x458CC58);
  } else {
  	cavium_error("SERDES_TUNING register value is improper\n");
  	return 1;
  }
  read_PKP_register(cvmdev, cvmdev->CSRBASE_A + N3_SERDES_TUNING, &dwval);
  if (dwval == 0x458CC58) {
  	cavium_print("SERDES_TUNING register value set: 0x%x\n", dwval);
  	return 0;
  } else
  	return 1;
}

#undef SPIN_FOR_ACK
#undef CLEAR_CMD
#undef WRITE_CMD
#undef DO_CMD

int get_core_frequency(cavium_device *pdev)
{
   Uint32 eclk1=0,eclk2=0;
   Uint32 freq=0;
   write_PKP_register(pdev, (pdev->CSRBASE_A+0x40058),0x750000ff);    
   cavium_udelay(10000);
   read_PKP_register(pdev, (pdev->CSRBASE_A+0x400A0), &eclk1);
   cavium_udelay(10000);
   write_PKP_register(pdev, (pdev->CSRBASE_A+0x40050),0x10000000);    
   read_PKP_register(pdev, (pdev->CSRBASE_A+0x400A0), &eclk2);
   freq=(eclk2-eclk1)/10000;
   if((freq > 480) && (freq < 520))
        return 500;
   if((freq > 580) && (freq < 620))
        return 600;
   if((freq > 680) && (freq < 720))
        return 700;
   if((freq > 730) && (freq < 770))
        return 750;
   if((freq > 780) && (freq < 820))
        return 800;
   if((freq > 980) && (freq < 1020))
        return 1000;
   return 0;
}
void 
enable_exec_masks_n3(cavium_device * pkp_dev)
{
   if (!n3_vf_driver) {
   Uint32 dwval;
   int i=0;
   Uint8 *offset;
   MPRINTFLOW();
   dwval=0x1;
   for(i=0;i<MAX_N3_QUEUES;i++)
   {
    if(boot_time){
     if(i<32){
      dwval=((Uint32)1<<i);
      offset=pkp_dev->CSRBASE_A + (N3_IQM0_EXEC_MSK_LO+(i<<8));
      write_PKP_register(pkp_dev, offset, dwval);
      cavium_udelay(10);
       dwval=0;
      offset=pkp_dev->CSRBASE_A + (N3_IQM0_EXEC_MSK_HI+(i<<8));
      write_PKP_register(pkp_dev, offset, dwval);
      cavium_udelay(10);
     }else{
      dwval=0;
      offset=pkp_dev->CSRBASE_A + (N3_IQM0_EXEC_MSK_LO+(i<<8));
      write_PKP_register(pkp_dev, offset, dwval);
      cavium_udelay(10);
      dwval=((Uint32)1<<(i-32));
      offset=pkp_dev->CSRBASE_A + (N3_IQM0_EXEC_MSK_HI+(i<<8));
      write_PKP_register(pkp_dev, offset, dwval);
      cavium_udelay(10);
     }
   }else{
     dwval=pkp_dev->CORE_MASK_0;
     offset=pkp_dev->CSRBASE_A + (N3_IQM0_EXEC_MSK_LO+(i<<8));
     write_PKP_register(pkp_dev, offset, dwval);
     dwval=pkp_dev->CORE_MASK_1;
     offset=pkp_dev->CSRBASE_A + (N3_IQM0_EXEC_MSK_HI+(i<<8));
     write_PKP_register(pkp_dev, offset, dwval);
   }
  }
  } else {
	return;
  }
}

void 
enable_request_unit_n3(cavium_device * pkp_dev)
{
   Uint32 dwval;
   MPRINTFLOW();
   dwval=0xffffffff;
   if (!n3_vf_driver)
	enable_exec_masks_n3(pkp_dev);

    write_PKP_register(pkp_dev,pkp_dev->CSRBASE_A+N3_IQM_EN_LO, dwval);
    cavium_udelay(10);
    if (!n3_vf_driver) {
    write_PKP_register(pkp_dev,pkp_dev->CSRBASE_A+N3_IQM_EN_HI, dwval);
    cavium_udelay(10);
    }
}

void 
disable_exec_masks_n3(cavium_device * pkp_dev)
{
   if (!n3_vf_driver) {
   Uint32 dwval;
   int i=0;
   Uint8 *offset;
   MPRINTFLOW();
   for(i=0;i<MAX_N3_QUEUES;i++)
   {
    dwval=0x0;
    offset=pkp_dev->CSRBASE_A + (N3_IQM0_EXEC_MSK_LO+(i<<8));
    write_PKP_register(pkp_dev, offset, dwval);
    offset=pkp_dev->CSRBASE_A + (N3_IQM0_EXEC_MSK_HI+(i<<8));
    write_PKP_register(pkp_dev, offset, dwval);
    cavium_udelay(10);
   }
   }
}


void 
disable_request_unit_n3(cavium_device *pkp_dev)
{
   Uint32 dwval;

    MPRINTFLOW();
    dwval=0;
    write_PKP_register(pkp_dev,pkp_dev->CSRBASE_A+N3_IQM_EN_LO, dwval);
    cavium_udelay(10);
    if (!n3_vf_driver) {
	int i;
	Uint8  *offset;
    write_PKP_register(pkp_dev,pkp_dev->CSRBASE_A+N3_IQM_EN_HI, dwval);
    cavium_udelay(10);
   for(i=0;i<MAX_N3_QUEUES;i++)
   {
     offset=pkp_dev->CSRBASE_A + (N3_IQM0_EXEC_MSK_LO+(i<<8));
     write_PKP_register(pkp_dev, offset, dwval);
     cavium_udelay(10);
     offset=pkp_dev->CSRBASE_A + (N3_IQM0_EXEC_MSK_HI+(i<<8));
     write_PKP_register(pkp_dev, offset, dwval);
     cavium_udelay(10);
    }
  }
}


void
disable_exec_units_from_mask_n3(cavium_device *pkp_dev, Uint64 mask)
{
   if (!n3_vf_driver) {
   Uint32 dwval = 0;
   Uint32 offset;
   int i,bit;
   MPRINTFLOW();
   for(i=0;i<pkp_dev->max_cores;i++)
   {
      bit=(mask>>i)&0x1;
      if(!bit) continue;
      bit=i%4;
      offset=N3_CORE_EN_0 + (bit*0x10000);
      read_PKP_register(pkp_dev,pkp_dev->CSRBASE_A + offset, &dwval);
      cavium_udelay(10);
      bit=i/4;
      dwval&= ~(((Uint16)1)<<bit);
      write_PKP_register(pkp_dev,pkp_dev->CSRBASE_A + offset, dwval);
      
    }   
  }  
}

void 
disable_all_exec_units_n3(cavium_device * pkp_dev)
{
   if (!n3_vf_driver) {
   Uint32 dwval;
   int m,n;
   Uint32 offset=0;
   MPRINTFLOW();
   /* make sure that cores are free */
   for(m=0;m<4;m++)
   {
     for(n=0;n<14;n++)
     {
       while(1){
         offset=0x0F8+(n*0x800)+m*0x10000+0x40000;
         read_PKP_register(pkp_dev, (pkp_dev->CSRBASE_A+offset), &dwval); 
         if(dwval&0x40000000){
            printk(KERN_CRIT "Core %d in cluster %d is doing busy.. Try Again: %x \n",n,m,dwval);
           cavium_udelay(100);
         }else
           break;
       }
     }
   }
   dwval=0;
   write_PKP_register(pkp_dev,pkp_dev->CSRBASE_A + N3_CORE_EN_0, dwval);
   cavium_udelay(10);
   write_PKP_register(pkp_dev,pkp_dev->CSRBASE_A + N3_CORE_EN_1, dwval);
   cavium_udelay(10);
   write_PKP_register(pkp_dev,pkp_dev->CSRBASE_A + N3_CORE_EN_2, dwval);
   cavium_udelay(10);
   write_PKP_register(pkp_dev,pkp_dev->CSRBASE_A + N3_CORE_EN_3, dwval);
   cavium_udelay(10);
 }
}

Uint32 get_coremask(int cores)
{
   Uint32 dwval=0;
   int i;
   for(i=0;i<cores;i++)
    dwval|=(1<<i);
   return dwval;
}
void
enable_exec_units_n3(cavium_device * pkp_dev)
{
   if (!n3_vf_driver) {
   Uint32 dwval;
   int cores_per_cluster=pkp_dev->max_cores/4;
   int cores_remaining=pkp_dev->max_cores%4;
   int cores=0;
    MPRINTFLOW();
    if(cores_remaining){
       cores=cores_per_cluster+1;
       cores_remaining--;
    }else
      cores=cores_per_cluster;
    dwval=get_coremask(cores);
    write_PKP_register(pkp_dev,pkp_dev->CSRBASE_A + N3_CORE_EN_0, dwval);
    cavium_udelay(10);

    if(cores_remaining){
       cores=cores_per_cluster+1;
       cores_remaining--;
    }else
      cores=cores_per_cluster;
    dwval=get_coremask(cores);
    write_PKP_register(pkp_dev,pkp_dev->CSRBASE_A + N3_CORE_EN_1, dwval);
    cavium_udelay(10);
    if(cores_remaining){
       cores=cores_per_cluster+1;
       cores_remaining--;
    }else
      cores=cores_per_cluster;
    dwval=get_coremask(cores);
    write_PKP_register(pkp_dev,pkp_dev->CSRBASE_A + N3_CORE_EN_2, dwval);
    cavium_udelay(10);
    if(cores_remaining){
       cores=cores_per_cluster+1;
       cores_remaining--;
    }else
      cores=cores_per_cluster;
    dwval=get_coremask(cores);
    write_PKP_register(pkp_dev,pkp_dev->CSRBASE_A + N3_CORE_EN_3, dwval);
    cavium_udelay(10);
   }
}


void
enable_exec_units_from_mask_n3(cavium_device * pkp_dev, Uint64 mask)
{
  if (!n3_vf_driver) {
   Uint32 dwval=0;
   Uint32 offset;
   int i,bit=0;
    MPRINTFLOW();
    for(i=0;i<pkp_dev->max_cores;i++)
    {
      bit=(mask>>i)&0x1;
      if(!bit) continue;
      bit=i%4;
      offset=N3_CORE_EN_0 + (bit*0x10000);
      read_PKP_register(pkp_dev,pkp_dev->CSRBASE_A + offset, &dwval);
      cavium_udelay(10);
      bit=i/4;
      dwval|= (1<<bit);
      write_PKP_register(pkp_dev,pkp_dev->CSRBASE_A + offset, dwval);
      
    }   
  }
}

void 
setup_request_queues_n3(cavium_device * pkp_dev)
{
    volatile Uint64 queue_base=0;
    volatile Uint32 length=0;
   int i;
    Uint32 offset;

    MPRINTFLOW();
    length = pkp_dev->command_queue_max;
 
 /* setup Request Queues */
    for(i = 0; i < pkp_dev->max_queues; i++) 
    {
     queue_base = (Uint64) pkp_dev->command_queue_bus_addr[i];
       cavium_dbgprint ("queue_base = 0x%llx\n", CAST64(queue_base));
       cavium_dbgprint ("queue_length = %x\n", length);
       cavium_udelay(1000);
       offset=N3_IQM0_BASE_ADDR_LO+(i<<8);
       write_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A+offset), (queue_base & 0xffffffff));
       cavium_udelay(1000);
       offset=N3_IQM0_BASE_ADDR_HI+(i<<8);
       write_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A + offset),  ((queue_base & 0xffffffff00000000ULL) >> 32));
       cavium_udelay(1000);
       offset=N3_IQM0_QSIZE+(i<<8);
       write_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A+offset), length);
       cavium_udelay(1000);
    }
}


void 
enable_data_swap_n3(cavium_device * pkp_dev)
{
   Uint32 dwval=0;
    MPRINTFLOW();
    read_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A + N3_CMD_REG), &dwval);
    cavium_udelay(10); 

   dwval = dwval | 0xf;
   write_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A + N3_CMD_REG), dwval);
}

void
enable_rnd_entropy_n3(cavium_device *pkp_dev)
{
   Uint32 dwval=0x3;
   write_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A + N3_RNM_CTL_STATUS), dwval);
   cavium_udelay(10); 
}

Uint32 
get_exec_units_n3(cavium_device * pkp_dev)
{
   Uint32 ret = 0;

    MPRINTFLOW();
    if (!n3_vf_driver) {
     Uint32 dwval = 0;
   /* now determine how many exec units are present */
   read_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A + N3_CORE_AVAIL_0), &dwval);
   ret += count_set_bits(dwval, 14);
   cavium_udelay(10);
   read_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A + N3_CORE_AVAIL_1), &dwval);
   ret += count_set_bits(dwval, 14);
   cavium_udelay(10);
   read_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A + N3_CORE_AVAIL_2), &dwval);
   ret += count_set_bits(dwval, 14);
   cavium_udelay(10);
   read_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A + N3_CORE_AVAIL_3), &dwval);
   ret += count_set_bits(dwval, 14);
   return ret;
   } else {
	return pkp_dev->max_cores;
   }
} /*int get_exec_units(void)*/


void cavium_load_credits(cavium_device *pdev)
{
  Uint32 dwval=0x111;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval=0x10111;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x20118;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x30114;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x40116;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x50116;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x60116;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x70116;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x1011;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x41001;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x51001;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x61001;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x71001;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x2c58;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x3412;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x43011;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x53011;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x63011;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x73011;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x4325;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x14111;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x34033;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
 dwval = 0x5325;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x15111;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x35033;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x6325;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x16111;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x36033;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x7325;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x17111;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
  dwval = 0x37033;
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_OCC_CREDIT_CTRL), dwval);
  udelay(100);
}

int cavium_check_bist(cavium_device *pdev)
{
   Uint32 dwval;
   read_PKP_register(pdev, (pdev->CSRBASE_A+0x10800), &dwval);
   if(dwval!=0x8c)
     goto bist_err;
   read_PKP_register(pdev, (pdev->CSRBASE_A+0x10808), &dwval);
   if(dwval!=0x0)
     goto bist_err;
   read_PKP_register(pdev, (pdev->CSRBASE_A+0x10810), &dwval);
   if(dwval!=0x55555555)
     goto bist_err;
   read_PKP_register(pdev, (pdev->CSRBASE_A+0x10818), &dwval);
   if(dwval!=0x55555555)
     goto bist_err;
   read_PKP_register(pdev, (pdev->CSRBASE_A+0x10820), &dwval);
   if(dwval!=0x55555555)
     goto bist_err;
   read_PKP_register(pdev, (pdev->CSRBASE_A+0x10828), &dwval);
   if(dwval!=0x55555555)
     goto bist_err;
   read_PKP_register(pdev, (pdev->CSRBASE_A+0x10830), &dwval);
   if(dwval!=0x55555555)
     goto bist_err;
   read_PKP_register(pdev, (pdev->CSRBASE_A+0x10838), &dwval);
   if(dwval!=0x55555555)
     goto bist_err;
   read_PKP_register(pdev, (pdev->CSRBASE_A+0x10840), &dwval);
   if(dwval!=0x55555555)
     goto bist_err;
   read_PKP_register(pdev, (pdev->CSRBASE_A+0x10848), &dwval);
   if(dwval!=0x55555555)
     goto bist_err;
   read_PKP_register(pdev, (pdev->CSRBASE_A+0x10850), &dwval);
   if(dwval!=0x55555555)
     goto bist_err;
  return 0;
bist_err:
    printk(KERN_CRIT "Bist Failed\n");
    return 1;
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

