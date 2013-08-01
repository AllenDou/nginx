/* interrupt.c */
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
#include "error_handler.h"
#include "interrupt.h"
#include "hw_lib.h"
extern int nr_cpus;
extern int n3_vf_driver;
extern struct delayed_work work[];
#ifdef INTERRUPT_COALESCING
Uint32 int_count_thold;
Uint32 int_time_thold;
#endif
/*
 * interrupt handler
 */
int handle_core_interrupts(cavium_device *pdev)
{
#ifdef ERROR_RECOVERY
   do_soft_reset(pdev);
#endif
#ifdef INTERRUPT_RETURN
      return 0;
#else
      return;
#endif
   
}
int handle_iqm_interrupt(cavium_device *pdev){
#ifdef ERROR_RECOVERY
   do_soft_reset(pdev);
#endif
#ifdef INTERRUPT_RETURN
      return 0;
#else
      return;
#endif
}
int handle_fatal_error(cavium_device *pdev){
#ifdef ERROR_RECOVERY
   do_soft_reset(pdev);
#endif
#ifdef INTERRUPT_RETURN
      return 0;
#else
      return;
#endif
}
#ifdef MSIX_ENABLED
int handle_completion_interrupt(int iqm, cavium_device *pdev)
#else
int handle_completion_interrupt(cavium_device *pdev)
#endif
{
#ifndef MSIX_ENABLED
  int i;
  Uint32 check_val=0;
#endif
  Uint32 dwval1=0;
  Uint32 dwval=0;
  Uint32 tval=0;
  Uint32 j=0;

  read_PKP_register(pdev, (pdev->CSRBASE_A + N3_COMPL_STATUS_SET), &dwval);
#ifdef MSIX_ENABLED
  j=iqm;
  read_PKP_register(pdev, (pdev->CSRBASE_A + N3_IQM0_CMP_CNT + (iqm*0x40)), &dwval1);
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_IQM0_CNT_SUB + (iqm*0x40)), dwval1);
  while(j < nr_cpus)
  {
     schedule_work_on(j, &((&work[j])->work));
     j+=8;
  } 
  tval = 3 << (iqm * 4);
  tval = dwval & tval;
  write_PKP_register(pdev, pdev->CSRBASE_A + N3_COMPL_STATUS_CLR, tval);
#else
  for(i=0;i<8;i++)
  {
     check_val=((Uint32)0x3)<<(i*4);
     if(dwval&check_val)
     {
        read_PKP_register(pdev, (pdev->CSRBASE_A + N3_IQM0_CMP_CNT + (i*0x40)), &dwval1);
        write_PKP_register(pdev, (pdev->CSRBASE_A + N3_IQM0_CNT_SUB + (i*0x40)), dwval1);
        j=i;
        while(j < nr_cpus){
          schedule_work_on(j,&((&work[j])->work));
          j+=8;
        }
        tval=(3<<(i*4));
        tval=dwval&tval;
        write_PKP_register(pdev, pdev->CSRBASE_A + N3_COMPL_STATUS_CLR, tval); 
     }
   }
#endif
   if(*((Uint8 *)pdev->error_val) != 0xff)
   {
       cavium_dump("error_val", (Uint8 *)pdev->error_val, 8);
       *((Uint8 *)pdev->error_val) = 0xff;
   }
#ifdef INTERRUPT_RETURN
      return 0;
#else
      return;
#endif
}

#ifdef INTERRUPT_RETURN
int
#else
void 
#endif
#ifdef MSIX_ENABLED
cavium_interrupt_handler_n3(int irq, void *arg)
#else
cavium_interrupt_handler_n3(void *arg)
#endif
{
   Uint32 dwval1=0;
   Uint32 dwval2=0;
   Uint32 dwval3=0;
   Uint32 dwval4=0;
   Uint32 dwval6=0;
   Uint32 dwiqm=0;
   Uint32 dwval=0;
   cavium_device *pdev;
#ifdef MSIX_ENABLED
   int i;
#endif
   pdev = (cavium_device *)arg;
   
   if (!n3_vf_driver) { 
   read_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_ISR_0), &dwval1);
   read_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_ISR_1), &dwval2);
   read_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_ISR_2), &dwval3);
   read_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_ISR_3), &dwval4);
   read_PKP_register(pdev,(pdev->CSRBASE_A + N3_HSI_ERR_STAT_CLR), &dwval6);
   if(dwval1==0  &&  dwval2==0 &&  dwval3==0 && dwval4==0 && dwval6==0){
      read_PKP_register(pdev, (pdev->CSRBASE_A+N3_IQM_INT_STAT),&dwiqm);
      read_PKP_register(pdev, (pdev->CSRBASE_A + N3_COMPL_STATUS_SET), &dwval);
      if(dwiqm==0 || dwval){
#ifdef INTERRUPT_RETURN
         return -1;
#else
         return;
#endif
     }
   }
   /* 
    * now since we know that it is pkp who has interrupted, 
    * mask all the interrupts 
    */
    write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_INT_EN_0),0x0);
    write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_INT_EN_1),0x0);
    write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_INT_EN_2),0x0);
    write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_INT_EN_3),0x0);
    write_PKP_register(pdev,(pdev->CSRBASE_A + N3_IQM_DBE_EN_HI),0x0);
    write_PKP_register(pdev,(pdev->CSRBASE_A + N3_IQM_OVFL_EN_HI),0x0);
    write_PKP_register(pdev,(pdev->CSRBASE_A + N3_IQM_WDOG_EN_HI),0x0);
    } //!n3_vf_driver

    write_PKP_register(pdev,(pdev->CSRBASE_A + N3_IQM_DBE_EN_LO),0x0);
    write_PKP_register(pdev,(pdev->CSRBASE_A + N3_IQM_OVFL_EN_LO),0x0);
    write_PKP_register(pdev,(pdev->CSRBASE_A + N3_IQM_WDOG_EN_LO),0x0);
   if(*((Uint8 *)pdev->error_val) != 0xff)
   {
       cavium_dump("error_val", (Uint8 *)pdev->error_val, 8);
       *((Uint8 *)pdev->error_val) = 0xff;
   }
#ifdef MSIX_ENABLED
   for(i=1; i < pdev->numvecs-2; i+=2)
   {
      if(irq == pdev->msix_entries[i].vector)
      {
           handle_completion_interrupt((i-1)/2, pdev);
           goto enables;
      }
   }
#else
   read_PKP_register(pdev, (pdev->CSRBASE_A + N3_COMPL_STATUS_SET), &dwval);
   if(dwval) //General IQM interrupt
   {
    handle_completion_interrupt(pdev);
    write_PKP_register(pdev, pdev->CSRBASE_A + N3_COMPL_STATUS_CLR, dwval); 
    goto enables;
   }
#endif

   if (!n3_vf_driver) {
   if(dwval1 || dwval2 || dwval3 || dwval4) //CORE Error occured
   {
    if((dwval1 &0x8) || (dwval2 &0x8) || (dwval3&0x8) || (dwval4&0x8))
        printk(KERN_CRIT "\n Core Watch dog Timeout %x:%x:%x:%x \n",dwval1,dwval2, dwval3,dwval4);
    if((dwval1 &0x4) || (dwval2 &0x4) || (dwval3&0x4) || (dwval4&0x4))
        printk(KERN_CRIT "\n Core RegFileError  %x:%x:%x:%x \n",dwval1,dwval2, dwval3,dwval4);
    if((dwval1 &0x2) || (dwval2 &0x2) || (dwval3&0x2) || (dwval4&0x2))
        printk(KERN_CRIT "\n microcode error interrupt occured  %x:%x:%x:%x \n",dwval1,dwval2, dwval3,dwval4);
    if((dwval1 &0x1) || (dwval2 &0x1) || (dwval3&0x1) || (dwval4&0x1))
        printk(KERN_CRIT "\n data read/store parity error occured  %x:%x:%x:%x \n",dwval1,dwval2, dwval3,dwval4);
     return handle_core_interrupts(pdev);
   }
  
  /* Handle IQM errors */
  
  read_PKP_register(pdev, (pdev->CSRBASE_A + N3_IQM_INT_STAT), &dwval);
  if(dwval & 0x3f)
  {
     return handle_iqm_interrupt(pdev);
  }
  /* Handle FATAL errors includes IQM FSK CRYPTO */
  read_PKP_register(pdev, (pdev->CSRBASE_A + N3_GEN_ERR_STATUS_CLR), &dwval);
  if(dwval & 0xAA001B3F) 
 {
    read_PKP_register(pdev, (pdev->CSRBASE_A + N3_HSI_ERR_STAT_CLR), &dwval1);
    dwval1&=~((Uint32)0x2000);
   if(dwval1){
    write_PKP_register(pdev, (pdev->CSRBASE_A + N3_HSI_ERR_STAT_CLR), dwval1);
    cavium_error("FATAL error occured %x",dwval); 
    return handle_fatal_error(pdev);
   }
 }

  /* Handle Non FATAL errors includes IQM FSK CRYPTO */
 if(dwval) 
 {
  /* clear GEN ERR register */
  write_PKP_register(pdev, (pdev->CSRBASE_A + N3_GEN_ERR_STATUS_CLR), dwval);
 }
 } //!n3_vf_driver
 
   /* Enable the interrupt status */
enables:
  pci_write_config_dword(pdev->dev, 0x60, 0);
  if (!n3_vf_driver) {
    dwval=0x1f; 
    write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_INT_EN_0),dwval);
    write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_INT_EN_1),dwval);
    write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_INT_EN_2),dwval);
    write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_INT_EN_3),dwval);
  }
   dwval=0xffffffff;
    write_PKP_register(pdev,(pdev->CSRBASE_A + N3_IQM_DBE_EN_LO),dwval);
    write_PKP_register(pdev,(pdev->CSRBASE_A + N3_IQM_OVFL_EN_LO),dwval);
    write_PKP_register(pdev,(pdev->CSRBASE_A + N3_IQM_WDOG_EN_LO),dwval);
   if (!n3_vf_driver) {
    write_PKP_register(pdev,(pdev->CSRBASE_A + N3_IQM_WDOG_EN_HI),dwval);
    write_PKP_register(pdev,(pdev->CSRBASE_A + N3_IQM_DBE_EN_HI),dwval);
    write_PKP_register(pdev,(pdev->CSRBASE_A + N3_IQM_OVFL_EN_HI),dwval);
   }
   /* restore interrupts */

#ifdef INTERRUPT_RETURN
   return 0;
#else
   return;
#endif
 
}/* cavium_interrupt_handler */

#ifdef INTERRUPT_RETURN
int
#else
void 
#endif
#ifdef MSIX_ENABLED
cavium_interrupt_handler_px(int irq, void *arg)
#else
cavium_interrupt_handler_px(void *arg)
#endif
{
   Uint32 dwval=0;
   int error_code =0;
   cavium_device *pdev;
#ifdef INTERRUPT_COALESCING
   static int int_time_hit, int_count_hit; //check for consequtive hits
#endif

   pdev = (cavium_device *)arg;
   /* first check to see if pkp has interrupted */
   read_PKP_register(pdev, (pdev->CSRBASE_A + ISR_REG), &dwval);

   if (dwval == 0) {
      read_PKP_register(pdev,(pdev->CSRBASE_A+PCI_ERR_REG), &dwval);
      if (dwval == 0) {
#ifdef INTERRUPT_RETURN
         return -1;
#else
         return;
#endif
      }
   }
 
   /* 
    * now since we know that it is pkp who has interrupted, 
    * mask all the interrupts 
    */
   write_PKP_register(pdev, (pdev->CSRBASE_A + IMR_REG), 0);

   /* check if general error has occured*/
   if(dwval & 8) 
   {
#ifdef MC2
#define LARGE_ERROR_VAL   (2*1024)
      int dump_size = 8;
#ifdef MCODE_LARGE_DUMP
      dump_size = LARGE_ERROR_VAL;
#endif
   if(cavium_debug_level >= 1)
      if((*((Uint8 *)pdev->error_val))!=0xff){
            cavium_dump("error_val", (Uint8 *)pdev->error_val, dump_size);
      *((Uint8 *)pdev->error_val)=0xff;
   }
      
#endif
      write_PKP_register(pdev,(pdev->CSRBASE_A + ISR_REG), dwval);
      write_PKP_register(pdev,(pdev->CSRBASE_A + IMR_REG), pdev->imr);
#ifdef INTERRUPT_RETURN
      return 0;
#else
      return;
#endif
   }
#ifdef INTERRUPT_COALESCING
  else if(dwval & 0x20000)   /* GENINT_THOLD_COUNT */
   { 
	  Uint16 pending_count=0;
	  int genint_count = 0;
      read_PKP_register(pdev, (pdev->CSRBASE_A + GENINT_COUNT_REG), &genint_count);
      write_PKP_register(pdev,(pdev->CSRBASE_A + GENINT_COUNT_SUB_REG),(Uint32) genint_count);
      write_PKP_register(pdev,(pdev->CSRBASE_A + ISR_REG), dwval);
      write_PKP_register(pdev,(pdev->CSRBASE_A + IMR_REG), pdev->imr);
      schedule_work_on(0,&((&work[0])->work));
      if(nr_cpus>=2)
           schedule_work_on(1,&((&work[1])->work));
      if(nr_cpus>=3)
           schedule_work_on(2,&((&work[2])->work));
      if(nr_cpus>=4)
           schedule_work_on(3,&((&work[3])->work));
#if 1
   int_count_hit++;
   int_time_hit=0;
   /* if count_thold hits 10 times consecutively */
   if (int_count_hit > 10 && pending_count >= 2) {
	  int_count_hit = 0;
	  if (int_count_thold < MAX_INT_COUNT_THOLD && pending_count > int_count_thold){
	     int_count_thold += (int_count_thold < 10)?2:4;
	     cavium_print ("GENINT_COUNT_THOLD_REG increased to %d\n", int_count_thold);
         write_PKP_register(pdev, (pdev->CSRBASE_A+GENINT_COUNT_THOLD_REG), int_count_thold);
      }
   }
#endif


#ifdef INTERRUPT_RETURN
      return 0;
#else
      return;
#endif
}  else if(dwval & 0x40000) /* GENINT_COUNT_TIME */
  { 
      write_PKP_register(pdev,(pdev->CSRBASE_A + ISR_REG), dwval);
      write_PKP_register(pdev,(pdev->CSRBASE_A + IMR_REG), pdev->imr);
#if 1
      int_time_hit++;
      int_count_hit=0;
      if (int_time_hit > 10) { /* if time hits 10 times consecutively */
         int_time_hit = 0;
         if (int_count_thold-2 >= 1)
         {
            int genint_count = 0;

            int_count_thold -= 2;
            cavium_print ("GENINT_COUNT_THOLD_REG decreased to %d\n", int_count_thold);
            read_PKP_register(pdev, (pdev->CSRBASE_A + GENINT_COUNT_REG), &genint_count);
            write_PKP_register(pdev, (pdev->CSRBASE_A+GENINT_COUNT_THOLD_REG), int_count_thold);
            write_PKP_register(pdev,(pdev->CSRBASE_A + GENINT_COUNT_SUB_REG),(Uint32) genint_count-((int_count_thold==1)?0:1));
           schedule_work_on(0,&((&work[0])->work));
           if(nr_cpus>=2)
               schedule_work_on(1,&((&work[1])->work));
           if(nr_cpus>=3)
               schedule_work_on(2,&((&work[2])->work));
           if(nr_cpus>=4)
               schedule_work_on(3,&((&work[3])->work));
         }
      }
#endif


#ifdef INTERRUPT_RETURN
      return 0;
#else
      return;
#endif
}    
#endif 
else if (dwval & 0x10) 
   {
      cavium_print("cavium_interrupt: EXEC unit watchdog timeout.\n");
   } else if ((error_code = check_hard_reset_group(pdev))) 
   {
      /* hard reset group */ 
      cavium_print("HArd Reset Group\n");
      handle_hard_reset(pdev);  /* :-) */
      clear_error(pdev, error_code);
    } else if ((error_code = check_soft_reset_group(pdev))) 
    {
      /* soft reset group */
      cavium_print("Soft Reset Group\n");
      handle_soft_reset(pdev);
      clear_error(pdev,error_code);
   } else if ((error_code = check_exec_reset_group(pdev))) 
   {
      /* exec reset group */
      cavium_print("Exec reset group \n");
      handle_exec_reset(pdev);
      clear_error(pdev,error_code);
   } else if ((error_code = check_seq_no_group(pdev))) 
   {
      /* the others */
      cavium_print("Sequence Number group \n");
      handle_seq_no_error(pdev);
      clear_error(pdev,error_code);
   } else 
   {
      /* Oops! whats this? */
      cavium_error("pkp: undocumented interrupt occured. ISR= %08x\n", 
              dwval);
   }

   /* clear the interrupt status */
   write_PKP_register(pdev,(pdev->CSRBASE_A + ISR_REG), dwval);

   /* restore interrupts */
   write_PKP_register(pdev,(pdev->CSRBASE_A + IMR_REG), pdev->imr);

#ifdef INTERRUPT_RETURN
   return 0;
#else
   return;
#endif
 
}/* cavium_interrupt_handler */

int 
enable_all_interrupts_n3(cavium_device * pdev)
{
   Uint32 dwval;
   int i;
   Uint32 offset=0;
   int count_thold = GENINT_COUNT_THOLD;
   int time_thold = GENINT_COUNT_INT_TIME;
  {
       dwval=0x0000001f;
       write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_INT_EN_0),dwval);
       cavium_udelay(10);
       write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_INT_EN_1),dwval);
       cavium_udelay(10);
       write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_INT_EN_2),dwval);
       cavium_udelay(10);
       write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_INT_EN_3),dwval);
       cavium_udelay(10);
       write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_FINT_EN_0),dwval);
       cavium_udelay(10);
       write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_FINT_EN_1),dwval);
       cavium_udelay(10);
       write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_FINT_EN_2),dwval);
       cavium_udelay(10);
       write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_FINT_EN_3),dwval);
       cavium_udelay(10);
       for(i=0;i<8;i++)
       {
       /* Enable Count Threshold and Timer Threshold Values */
        offset=N3_IQM0_CNT_THOLD+(0x40*i);
         write_PKP_register(pdev, (pdev->CSRBASE_A+offset), count_thold);
         cavium_udelay(10);
        /*Neeed to Program Timer Register */
         offset=N3_IQM0_TIM_LD+(0x40*i);
         write_PKP_register(pdev, (pdev->CSRBASE_A+offset), time_thold);
         cavium_udelay(10);
       }
       /* Enable IQM Interrupts */
       dwval=0xffffffff;
       write_PKP_register(pdev, (pdev->CSRBASE_A+N3_IQM_DBE_EN_LO), dwval);      
       cavium_udelay(10);
       write_PKP_register(pdev, (pdev->CSRBASE_A+N3_IQM_DBE_EN_HI), dwval);      
       cavium_udelay(10);
       write_PKP_register(pdev, (pdev->CSRBASE_A+N3_IQM_OVFL_EN_LO), dwval);      
       cavium_udelay(10);
       write_PKP_register(pdev, (pdev->CSRBASE_A+N3_IQM_OVFL_EN_HI), dwval);      
       cavium_udelay(10);
       write_PKP_register(pdev, (pdev->CSRBASE_A+N3_IQM_WDOG_EN_LO), dwval);      
       cavium_udelay(10);
       write_PKP_register(pdev, (pdev->CSRBASE_A+N3_IQM_WDOG_EN_HI), dwval);
       cavium_udelay(10);
  }
   return 0;
} /* enable_all_interrupts*/

int 
enable_all_interrupts_px(cavium_device * pkp_dev)
{
   Uint32 imr_val, cr04_val, dwval;
#ifdef INTERRUPT_COALESCING
   int_count_thold = GENINT_COUNT_THOLD;
   int_time_thold = GENINT_COUNT_INT_TIME;
#endif
   imr_val = 0;
   cr04_val = 0;

   imr_val = BM_PCI_MASTER_ABORT_WRITE |
             BM_PCI_TARGET_ABORT_WRITE |
#ifdef INTERRUPT_COALESCING
             GI_TIM_ENABLE |
             GI_CNT_ENABLE |
#endif
             BM_PCI_MASTER_RETRY_TIMEOUT_WRITE |
             BM_PCI_ADD_ATTRIB_PHASE_PARITY |
             BM_PCI_MASTER_WRITE_PARITY |
             BM_PCI_TARGET_WRITE_DATA_PARITY |
             BM_MSI_TRANSACTION |
             BM_OUTBOUND_FIFO_CMD |
             BM_KEY_MEMORY_PARITY |
             BM_PCI_MASTER_ABORT_REQ_READ |
             BM_PCI_TARGET_ABORT_REQ_READ |
             BM_PCI_MASTER_RETRY_TIMEOUT_REQ_READ |
             BM_PCI_MASTER_DATA_PARITY_REQ_READ |
             BM_REQ_COUNTER_OVERFLOW |
             BM_EXEC_REG_FILE_PARITY |
             BM_EXEC_UCODE_PARITY |
             BM_PCI_MASTER_ABORT_EXEC_READ   |
             BM_PCI_TARGET_ABORT_EXEC_READ |
             BM_PCI_MASTER_RETRY_TIMOUT_EXEC_READ |
             BM_PCI_MASTER_DATA_PARITY_EXEC_READ |
             BM_EXEC_GENERAL |
             BM_CMC_DOUBLE_BIT |
             BM_CMC_SINGLE_BIT;


   cr04_val = BM_CR04_PCI_TARGET_ABORT_WRITE |
              BM_CR04_ADD_ATTRIB_PHASE_PARITY |
              BM_CR04_PCI_TARGET_ABORT_REQ_READ |
              BM_CR04_REQ_COUNTER_OVERFLOW |
              BM_CR04_PCI_TARGET_ABORT_EXEC_READ; 

   /* write Interrupt Mask Register */
   write_PKP_register(pkp_dev,(pkp_dev->CSRBASE_A+IMR_REG), imr_val);

   /* remember imr */
   pkp_dev->imr = imr_val;

   dwval = 0;
   read_PCI_register(pkp_dev, PCI_CONFIG_04, &dwval);

   cr04_val = cr04_val | dwval;
   write_PCI_register(pkp_dev, PCI_CONFIG_04,cr04_val);

#ifdef INTERRUPT_COALESCING
   write_PKP_register(pkp_dev, (pkp_dev->CSRBASE_A+GENINT_COUNT_THOLD_REG), int_count_thold);
   write_PKP_register(pkp_dev, (pkp_dev->CSRBASE_A+GENINT_COUNT_INT_TIME_REG), int_time_thold);
   #endif
   cavium_dbgprint("Interrupt Mask Register = %08x\n", imr_val);
   cavium_dbgprint("PCI Config 04 = %08x\n", cr04_val);
   return 0;
} /* enable_all_interrupts*/

/*
 * $Id: interrupt.c,v 1.6 2011/05/11 14:34:12 tghoriparti Exp $
 * $Log: interrupt.c,v $
 * Revision 1.6  2011/05/11 14:34:12  tghoriparti
 * FreeBSD porting for SDK 4.0
 *
 * Revision 1.5  2011/04/16 11:42:20  tghoriparti
 * Moved local variables required for Interrupt coalescing under INTERRUPT_COALESCING.
 *
 * Revision 1.4  2010/04/29 13:59:36  aravikumar
 * INT_COALSCING made dynamic based on pending list
 *
 * Revision 1.3  2008/12/22 05:42:10  jrana
 *  COUNTERS and INTERRUPT COALEASCING ADDED
 *
 * Revision 1.2  2008/09/30 13:15:17  jsrikanth
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
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.12  2006/01/31 07:00:55  sgadam
 * - Added pending entries and direct entries to special queue
 *
 * Revision 1.11  2005/11/17 13:31:09  kanantha
 * Updating with the 64 bit modifications, with proper matching of data types
 *
 * Revision 1.10  2005/10/13 09:24:39  ksnaren
 * fixed compile warnings
 *
 * Revision 1.9  2005/09/28 15:50:26  ksadasivuni
 * - Merging FreeBSD 6.0 AMD64 Release with CVS Head
 * - Now context pointer given to user space applications is physical pointer.
 *   So there is no need to do cavium_vtophys() of context pointer.
 *
 * Revision 1.8  2005/06/13 06:35:42  rkumar
 * Changed copyright
 *
 * Revision 1.7  2005/05/20 14:34:05  rkumar
 * Merging CVS head from india
 *
 * Revision 1.6  2005/02/01 04:11:07  bimran
 * copyright fix
 *
 * Revision 1.5  2004/06/23 20:38:35  bimran
 * compiler warnings on NetBSD.
 *
 * Revision 1.3  2004/05/02 19:44:29  bimran
 * Added Copyright notice.
 *
 * Revision 1.2  2004/04/29 00:21:24  bimran
 * Added error_val dump in case of MC2
 *
 * Revision 1.1  2004/04/15 22:40:49  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

