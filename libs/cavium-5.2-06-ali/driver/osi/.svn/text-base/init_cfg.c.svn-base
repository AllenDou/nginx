/* init_cfg.c */

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
#include "cavium_endian.h"
#include "cavium.h"
#include "init_cfg.h"
#include "microcode.h"
#include "interrupt.h"
#include "command_que.h"
#include "context_memory.h"
#include "hw_lib.h"
#include "error_handler.h"
#include "request_manager.h"
#include "buffer_pool.h"
#include "key_memory.h"
//#define LOAD_BOOT_ONLY
/*
 * Device driver general function
 */
int send_init_request(cavium_device *pdev);
void patch_it(Uint32 start_addr, Uint32 end_addr, struct CSP1_PATCH_WRITE *patch_write);
static struct MICROCODE *
get_microcode(cavium_device *pkp_dev, Uint8 type);

/*
 * Response queues procesing 
 */
/*
 * Global variables
 */
Uint64 cavium_command_timeout = 0;

extern short vf_count;
extern int n3_vf_driver;
Uint8 cavium_version[3] = {5,2,0};
int dev_count=0;
int first_round = 1;
int global_rnd[48+ALIGNMENT]={0};
cavium_device cavium_dev[MAX_DEV];
extern short nplus, ssl, ipsec, max_q;

int boot_time=1;
#ifndef LOAD_BOOT_ONLY
static int
pkp_boot_setup_ucode(cavium_device *pkp_dev, int ucode_idx);
#endif
static int
pkp_boot_init(cavium_device *pkp_dev);

/*
 *Initialize the chip, do core discovery, load microcode and send init requests.
 */
int max_cpus=0;
int max_device_queues=0;
int
cavium_init(cavium_config *config)
{
   int i=0,j;
   int ret;
   cavium_device *pkp_dev;
   uint32_t dwval = 0;


   MPRINTFLOW();
   if(dev_count >= MAX_DEV) 
   {
      cavium_error("MAX_DEV reached.\n");
      goto init_error;
   }
   cavium_command_timeout = CAVIUM_DEFAULT_TIMEOUT;
   cavium_dbgprint("Inside cavium_init\n");
   /* cavium_memset(&cavium_dev[0],0x00,sizeof(cavium_dev));*/
   cavium_memset(&cavium_dev[dev_count], 0, sizeof(cavium_device)); 

   cavium_dev[dev_count].uen=0;
   cavium_dev[dev_count].enable=0;
   cavium_dev[dev_count].device_id=config->device_id;
   if(cavium_dev[dev_count].device_id == NPX_DEVICE){
    cavium_dev[dev_count].cavfns.enable_request_unit          = enable_request_unit_px; 
    cavium_dev[dev_count].cavfns.disable_request_unit         = disable_request_unit_px; 
    cavium_dev[dev_count].cavfns.disable_exec_units_from_mask = disable_exec_units_from_mask_px;
    cavium_dev[dev_count].cavfns.disable_all_exec_units       = disable_all_exec_units_px;
    cavium_dev[dev_count].cavfns.enable_exec_units            = enable_exec_units_px;
    cavium_dev[dev_count].cavfns.enable_exec_units_from_mask  = enable_exec_units_from_mask_px;
    cavium_dev[dev_count].cavfns.setup_request_queues         = setup_request_queues_px;
    cavium_dev[dev_count].cavfns.enable_data_swap             = enable_data_swap_px;
    cavium_dev[dev_count].cavfns.get_exec_units               = get_exec_units_px;
    cavium_dev[dev_count].cavfns.enable_rnd_entropy           = enable_rnd_entropy_px;
    cavium_dev[dev_count].cavfns.interrupt_handler            = cavium_interrupt_handler_px;
    cavium_dev[dev_count].cavfns.load_microcode               = load_microcode_px;
  }
  else if(cavium_dev[dev_count].device_id == N3_DEVICE){
    cavium_dev[dev_count].cavfns.enable_request_unit          = enable_request_unit_n3; 
    cavium_dev[dev_count].cavfns.disable_request_unit         = disable_request_unit_n3; 
    cavium_dev[dev_count].cavfns.disable_exec_units_from_mask = disable_exec_units_from_mask_n3;
    cavium_dev[dev_count].cavfns.disable_all_exec_units       = disable_all_exec_units_n3;
    cavium_dev[dev_count].cavfns.enable_exec_units            = enable_exec_units_n3;
    cavium_dev[dev_count].cavfns.enable_exec_units_from_mask  = enable_exec_units_from_mask_n3;
    cavium_dev[dev_count].cavfns.setup_request_queues         = setup_request_queues_n3;
    cavium_dev[dev_count].cavfns.enable_data_swap             = enable_data_swap_n3;
    cavium_dev[dev_count].cavfns.get_exec_units               = get_exec_units_n3;
    cavium_dev[dev_count].cavfns.enable_rnd_entropy           = enable_rnd_entropy_n3;
    cavium_dev[dev_count].cavfns.interrupt_handler            = cavium_interrupt_handler_n3;
    cavium_dev[dev_count].cavfns.load_microcode               = load_microcode_n3;
  }
   /* copy bar addresses and opaque device */
   cavium_dev[dev_count].dev = config->dev;
   cavium_dev[dev_count].px_flag = config->px_flag;
   cavium_dev[dev_count].bar_px = config->bar_px;
   cavium_dev[dev_count].bar_px_hw = config->bar_px_hw;
   cavium_dev[dev_count].csrbase_a = config->bar_px;
   cavium_dev[dev_count].csrbase_b = config->bar_px;
   cavium_dev[dev_count].bar_len = config->bar_len;
   cavium_dev[dev_count].bus_number = config->bus_number;
   cavium_dev[dev_count].dev_number = config->dev_number;
   cavium_dev[dev_count].func_number = config->func_number;
   cavium_dev[dev_count].command_queue_max = config->command_queue_max;
   cavium_spin_lock_init(&cavium_dev[dev_count].keymem_lock);
   if (!n3_vf_driver) {
   set_soft_reset(&cavium_dev[dev_count]);
   if(cavium_dev[dev_count].device_id == N3_DEVICE){
      if (fix_phy_calibration(&cavium_dev[dev_count]))
	 goto init_error; // Calibration failed
      if (tune_serdes(&cavium_dev[dev_count]))
	goto init_error; // Serdes Tuning failed 
      cavium_load_credits(&cavium_dev[dev_count]);
      if(cavium_check_bist(&cavium_dev[dev_count]))
          goto init_error; 
    }
   }
   if (nplus || ssl>0 || ipsec>0) 
   {
      for(i=0; i<MICROCODE_MAX-!nplus; i++)
      {
         cavium_dev[dev_count].microcode[i].core_id = (Uint8)-1;
         cavium_dev[dev_count].microcode[i].use_count = 0;
         cavium_dev[dev_count].microcode[i].code = NULL;
         cavium_dev[dev_count].microcode[i].data = NULL;
       	cavium_spin_lock_init(&(cavium_dev[dev_count].microcode[i].srq.lock));
      }
      cavium_spin_lock_init(&cavium_dev[dev_count].mc_core_lock);
      /* Init the UEN Register Spin lock */
      cavium_spin_lock_init(&cavium_dev[dev_count].uenreg_lock);
   }

#ifdef MC2

   cavium_dev[dev_count].scratchpad_base = (Uint8 *)cavium_malloc_nc_dma(
                           (&cavium_dev[dev_count]),
                           SCRATCHPAD_SIZE* MAX_CORES_NITROX,
                           &cavium_dev[dev_count].scratchpad_base_busaddr);
   if (cavium_dev[dev_count].scratchpad_base == NULL) 
   {
      cavium_error("cavium_init: Unable to allocate memory for Scratch Pad\n");
      goto init_error;
   }
   cavium_dbgprint("cavium_init: Scratchpad BASE 0x%p\n",cavium_dev[dev_count].scratchpad_base);

   cavium_memset(cavium_dev[dev_count].scratchpad_base, 0, SCRATCHPAD_SIZE*MAX_CORES_NITROX);

{
   int errval_size = 0;
#define LARGE_ERROR_VAL (2*1024)
#ifndef MCODE_LARGE_DUMP
   errval_size = sizeof(Uint64);
#else
   errval_size = LARGE_ERROR_VAL;
#endif
   cavium_dev[dev_count].error_val = (Uint64*)cavium_malloc_nc_dma(
                                      (&cavium_dev[dev_count]),
                                      errval_size,
                                      &cavium_dev[dev_count].error_val_busaddr);
}
   if (cavium_dev[dev_count].error_val == NULL) 
   {
      cavium_error("cavium_init: Unable to allocate memory for error_val\n");
      goto init_error;
   }
#endif
   pkp_dev = &cavium_dev[dev_count];
   if (!n3_vf_driver) {
   max_device_queues=(cavium_dev[dev_count].device_id==N3_DEVICE)?MAX_N3_QUEUES:MAX_N1_QUEUES;
   if(max_q > num_online_cpus())
   {
     //Will follow round robin method of submission
     if(max_q > max_device_queues)
        cavium_dev[dev_count].max_queues=max_device_queues;
     else
        cavium_dev[dev_count].max_queues=max_q;
     cavium_dev[dev_count].curr_q = 0; //init the queue number
   }
   else 
   {  
      max_q = 0; //Will do according to processor id
      cavium_dev[dev_count].max_queues=max_device_queues; //will be ignored, but set anyway

   }
   } else { //!n3_vf_driver
       /* Write 0xffffffff to request unit and read it.
        * The number of bits set gives the number of queues enabled.
        */
       pkp_dev->cavfns.enable_request_unit(pkp_dev);
       read_PKP_register(pkp_dev,pkp_dev->CSRBASE_A+N3_IQM_EN_LO, &dwval);
       pkp_dev->cavfns.disable_request_unit(pkp_dev);
       cavium_dbgprint("%s(): %d: N3_IQM_EN_LO: 0x%x\n", __func__, __LINE__, dwval);
       pkp_dev->max_queues = count_set_bits(dwval, 8); /* max 8 queues are possible per VF */
       vf_count = MAX_N3_QUEUES / pkp_dev->max_queues;
       cavium_dbgprint("%s(): %d: Queues enabled: 0x%x, VF_COUNT: %d\n", __func__, __LINE__, pkp_dev->max_queues, vf_count);
   }
   /* initialize command_queue */
   cavium_dbgprint("cavium_init: allocating command queues.\n");
   for (i = 0; i < cavium_dev[dev_count].max_queues; i++) 
   {
      cavium_spin_lock_init(&(cavium_dev[dev_count].command_queue_lock[i]));   
      if(init_command_queue(&cavium_dev[dev_count], i)) 
      { 
         cavium_error("init_command_queue failed\n");
         goto init_error;
      } 
      else 
      {
        if(cavium_dev[dev_count].device_id == NPX_DEVICE)
         cavium_dev[dev_count].door_addr[i] = ((ptrlong)cavium_dev[dev_count].CSRBASE_B + REQ0_DOOR_BELL + 0x20*i); 
        else if(cavium_dev[dev_count].device_id == N3_DEVICE)
         cavium_dev[dev_count].door_addr[i] = ((ptrlong)cavium_dev[dev_count].CSRBASE_A + N3_IQM0_DOOR_BELL_REG + 0x100*i);
     }
   /* Initialize Pending Queue */
      cavium_dev[dev_count].pending_queue[i].cmd_queue=(CMD_DATA *)kmalloc(sizeof(CMD_DATA)*MAX_PENDING_QUEUE_SIZE,GFP_ATOMIC);
     if(cavium_dev[dev_count].pending_queue[i].cmd_queue == NULL)
     {
         cavium_error("init_command_queue failed\n");
         goto init_error;
     }
      cavium_dev[dev_count].pending_queue[i].queue_size=MAX_PENDING_QUEUE_SIZE;
      cavium_spin_lock_init(&(cavium_dev[dev_count].pending_queue[i].pending_lock));
      cavium_dev[dev_count].pending_queue[i].queue_front=0;
      cavium_dev[dev_count].pending_queue[i].queue_rear=0;
      memset(cavium_dev[dev_count].pending_queue[i].cmd_queue,0x0, sizeof(CMD_DATA)*MAX_PENDING_QUEUE_SIZE);
     for(j=0;j<MAX_PENDING_QUEUE_SIZE;j++)
     {
         (cavium_dev[dev_count].pending_queue[i].cmd_queue)[j].free=1;
     }
  }

   /* initialize cavium_chip */
   cavium_dbgprint("cavium_init: clearing error regs,setting up command qs\n");

   if(pkp_init_board(&cavium_dev[dev_count])) 
   {
      cavium_error("pkp_init_board failed\n");
      goto init_error;
   }

   cavium_dev[dev_count].dram_max = config->context_max;
   cavium_dev[dev_count].dram_base = 0;

 
   /* allocate a pool of context memory chunks */
   cavium_dbgprint("cavium_general_init: init context.\n");
   if(init_context(&cavium_dev[dev_count])) 
   {
      ret = ERR_MEMORY_ALLOC_FAILURE;
      cavium_error("init_context failed\n");
      goto init_error;
   }

   /* do core discovery and init requests */
   cavium_dbgprint("cavium_init: doing core discovery, load microcode\n");

   /* enable interrupts */
   cavium_dbgprint("cavium_init: enabling error interrupts.\n");
  if(cavium_dev[dev_count].device_id == NPX_DEVICE)
    enable_all_interrupts_px(&cavium_dev[dev_count]);
  else if(cavium_dev[dev_count].device_id == N3_DEVICE)
   enable_all_interrupts_n3(&cavium_dev[dev_count]);
  else
   printk(KERN_CRIT "cavium_init: Interrupts are not enabled\n");

   find_cfg_part_initialize(&cavium_dev[dev_count]);  
   
   cavium_dbgprint("cavium_init: returning with success.\n");
   return 0;

init_error:
  
   for (i = 0; i <= dev_count; i++) 
   {
      cleanup_context(&cavium_dev[i]);
#ifdef MC2
      if (cavium_dev[i].scratchpad_base) 
      {
         cavium_free_nc_dma((&cavium_dev[i]),
                             SCRATCHPAD_SIZE * MAX_CORES_NITROX,
                             cavium_dev[i].scratchpad_base,
                             cavium_dev[i].scratchpad_base_busaddr);
       }
       if (cavium_dev[i].error_val) 
       {
#ifndef MCODE_LARGE_DUMP
          cavium_free_nc_dma((&cavium_dev[i]),sizeof(Uint64),
                             cavium_dev[dev_count].error_val,
                             cavium_dev[dev_count].error_val_busaddr);
#else
          cavium_free_nc_dma((&cavium_dev[i]), LARGE_ERROR_VAL,
                             cavium_dev[dev_count].error_val,
                             cavium_dev[dev_count].error_val_busaddr);
#endif
   }
#endif
    }
 
    for(i=0;i< cavium_dev[dev_count].max_queues;i++)
    {
       cavium_spin_lock_destroy(&(cavium_dev[dev_count].command_queue_lock[i]));
    } 
    for ( i = 0; i < cavium_dev[dev_count].max_queues; i++) 
    {
       cleanup_command_queue(&cavium_dev[dev_count], i);
       if(cavium_dev[dev_count].pending_queue[i].cmd_queue)
           kfree(cavium_dev[dev_count].pending_queue[i].cmd_queue);
       cavium_dev[dev_count].pending_queue[i].cmd_queue=NULL;
       cavium_spin_lock_destroy(&(cavium_dev[dev_count].pending_queue[i].pending_lock));
        
    }

   cavium_dbgprint("cavium_init: returning with failure.\n");
   return 1;
}/* cavium_init*/


typedef enum
{
   NONE_SUCCESS,
   INIT_BUFFER_POOL_SUCCESS,
   INIT_RND_BUFFER_SUCCESS,
   INIT_KEY_MEMORY_SUCCESS,
   INIT_COMPLETION_DMA_FREE_LIST_SUCCESS,
   INIT_PENDING_LISTS_SUCCESS,
   INIT_PENDING_FREE_LIST_SUCCESS,
   INIT_DIRECT_FREE_LIST_SUCCESS,   
   INIT_SG_FREE_LIST_SUCCESS,
   INIT_SG_DMA_FREE_LIST_SUCCESS,
   INIT_BLOCKING_NON_BLOCKING_LISTS_SUCCESS,
}cavium_general_init_status;


int cavium_general_init()
{
   int ret=0, i=0,j;
   cavium_general_init_status status = NONE_SUCCESS;   
   status = NONE_SUCCESS;
   cavium_dbgprint("cavium_general_init:init buffer pools.\n");
   if (init_buffer_pool())
   {
       ret = ERR_MEMORY_ALLOC_FAILURE;
       goto init_general_error;
   }
   status = INIT_BUFFER_POOL_SUCCESS;

   MPRINTFLOW();
   for (i = 0; i < dev_count; i++) 
   {
      /* initialize random pool */
      cavium_dbgprint("cavium_general_init:init rnd pool.\n");
      /* Initialize key memory chunks */
	  if (nplus || ssl>=0) 
	  {
         cavium_dbgprint("cavium_general_init:init key memory.\n");
         if (init_key_memory(&cavium_dev[i])) 
         {
            ret = ERR_MEMORY_ALLOC_FAILURE;
            goto init_general_error;
         }
         status = INIT_KEY_MEMORY_SUCCESS;
      }
   } /* dev loop */


   return ret;

init_general_error:
   switch(status)
   {
      case NONE_SUCCESS:
           return ret;
      case INIT_BUFFER_POOL_SUCCESS: 
      case INIT_KEY_MEMORY_SUCCESS:
      {
         for(j=i-1;j>=0;j--)
               if (ssl>=0 || nplus) cleanup_key_memory(&cavium_dev[i]);
         free_buffer_pool();
         break;
      }
      default:return ret;
      
   }   
   cavium_dbgprint("cavium_general_init: returning with failure.\n");
   return ret;

} /* general entry */


/*
 *  Standard module release function.
 */
void cavium_cleanup(void *dev)
{
    cavium_device *pdev = (cavium_device *)dev;
    int i;

    MPRINTFLOW();
     cavium_dbgprint("cavium_cleanup: entering\n");
   if (!n3_vf_driver) {
    set_soft_reset(pdev);
   if(pdev->device_id == N3_DEVICE){
      if (fix_phy_calibration(pdev))
	return; // Calibration failed
      if (tune_serdes(pdev))
	return; // Serdes Tuning failed 
      cavium_load_credits(pdev);
      cavium_check_bist(pdev);
    }
    }
    for(i=0;i<pdev->max_queues;i++)
    {
   cavium_spin_lock_destroy(&(pdev->command_queue_lock[i]));
    }    
    /* cleanup command queue */
    for (i = 0; i < pdev->max_queues; i++) 
    {
       cleanup_command_queue(pdev, i);
       if(pdev->pending_queue[i].cmd_queue)
           kfree(pdev->pending_queue[i].cmd_queue);
       pdev->pending_queue[i].cmd_queue=NULL;
       cavium_spin_lock_destroy(&(pdev->pending_queue[i].pending_lock));
    }
    cavium_dbgprint("cavium_cleanup: after cleanup_command_queue\n");
    cleanup_context(pdev);
    cavium_dbgprint("cavium_cleanup: after cleanup_context\n");
#ifdef MC2
    if (pdev->scratchpad_base) 
    {
      cavium_free_nc_dma(pdev,
                             SCRATCHPAD_SIZE * MAX_CORES_NITROX,
                             pdev->scratchpad_base,
                             pdev->scratchpad_base_busaddr);
    }
    cavium_dbgprint("cavium_cleanup: after freeing scratchpad_base\n");
    if (pdev->error_val) 
    {
#ifndef MCODE_LARGE_DUMP
        cavium_free_nc_dma(pdev,sizeof(Uint64),
                             pdev->error_val,
                             pdev->error_val_busaddr);
#else
        cavium_free_nc_dma(pdev, LARGE_ERROR_VAL,
                             pdev->error_val,
                             pdev->error_val_busaddr);
#endif
    }
    cavium_dbgprint("cavium_cleanup: after freeing error_val\n");
#endif
    return;
}


/*
 * General cleanup function
 */
int cavium_general_cleanup(void)
{
    int i;

   cavium_dbgprint("cavium_general_cleanup: entering\n");
   
   cavium_dbgprint("cavium_general_cleanup: after cleanup_pending_lists\n");
   for(i=0; i<dev_count; i++)
   {
       if (ssl>=0 || nplus)
        cleanup_key_memory(&cavium_dev[i]);
       {
          Uint8 j = 0;
          cavium_device *pdev = NULL;
          pdev = &cavium_dev[i];
          for(j=0; j< MICROCODE_MAX-!nplus; j++)
          {
             if(pdev->microcode[j].data)
             {
           
#ifdef MC2
                  cavium_free_nc_dma(pdev, 
                                pdev->microcode[j].data_size+40,
                                pdev->microcode[j].data,
                                pdev->microcode[j].data_dma_addr);                
#else
                  cavium_free_nc_dma(pdev, 
                                pdev->microcode[j].data_size,
                                pdev->microcode[j].data,
                                pdev->microcode[j].data_dma_addr);                
#endif            
                 put_buffer_in_pool(pdev->microcode[j].code, pdev->microcode[j].code_size); 
                  pdev->microcode[j].data=NULL;
                  pdev->microcode[j].data_size=0;
                  pdev->microcode[j].data_dma_addr=0;
             }
          }
      }

   }
   free_buffer_pool();
   cavium_dbgprint("cavium_general_cleanup: returning\n");
   return 0;
} /* cleanup general */


/*
 * get the microcode
 */
static struct MICROCODE *
get_microcode(cavium_device *pkp_dev, Uint8 type)
{
   struct MICROCODE *microcode;

   /* Same behavior for NITROX_PX  */ 
   if (nplus || ssl > 0 || ipsec > 0) {
      microcode = &pkp_dev->microcode[type];
      return microcode;
   }
   else 
   {
      int i;
      microcode = pkp_dev->microcode;

       MPRINTFLOW();
      for(i=0; i<MICROCODE_MAX-!nplus; i++)
      {
         if(microcode[i].code_type == type)
            return &microcode[i];
      }
   }

   return NULL;

}/* get_microcode*/

/*
 * pkp_boot_setup_ucode()
 */
#ifndef LOAD_BOOT_ONLY
static int
pkp_boot_setup_ucode(cavium_device *pkp_dev, int ucode_idx)
{
   struct MICROCODE *microcode;
   Request request;
   Cmd* strcmd = (Cmd*)&request;
   Uint64 *completion_address;
   Uint8 *outbuffer = NULL;
   int ret, srq_idx = -1;
   MPRINTFLOW();
	
//#ifdef NPLUS
//   if (nplus)
      microcode = get_microcode(pkp_dev, ucode_idx);
//#else
//   else 
//      microcode = get_microcode(pkp_dev, CODE_TYPE_MAINLINE);
//#endif

   if(microcode == NULL) 
   {
           cavium_print( 
             "Unable to get microcode struct in boot setup ucode\n");
           ret=1;
           goto boot_setup_err;
   }

   if(cavium_debug_level > 2)
   {
      cavium_dump("sram address", microcode->sram_address,8);
   }

   strcmd->opcode = htobe16(OP_BOOT_SETUP_UCODE);
   strcmd->size  = htobe16(0);
   strcmd->param = htobe16((Uint16)(betoh64(*(Uint64 *)
                           (microcode->sram_address))));
#ifndef MC2
   strcmd->dlen  = htobe16((Uint16)(microcode->data_size >> 3));
#else
   strcmd->dlen  = htobe16((Uint16)8);
#endif


   outbuffer = (Uint8 *)cavium_malloc_dma(8 + ALIGNMENT, NULL);



   if (outbuffer == NULL) 
   {
     cavium_error( "unable to allocate outbuffer in sending boot setup ucode\n");
     ret = 1;
     goto boot_setup_err;
   }

#ifndef MC2
 request.dptr = htobe64(microcode->data_dma_addr);
#else
 request.dptr = htobe64(microcode->data_dma_addr + 40);
#endif

 request.rptr = (Uint64)cavium_map_kernel_buffer(pkp_dev,
                   (((ptrlong)outbuffer + ALIGNMENT) & ALIGNMENT_MASK),
                   8,
                   CAVIUM_PCI_DMA_BIDIRECTIONAL);


   if(!request.rptr)
   {
     cavium_error( "unable to map kernel buffer in sending boot setup ucode\n");
     ret = 1;
     goto boot_setup_err;
   }
   request.rptr = htobe64(request.rptr);

   request.cptr = htobe64(0);

   completion_address = (Uint64 *)(((ptrlong)outbuffer + ALIGNMENT) & ALIGNMENT_MASK);

   *completion_address = COMPLETION_CODE_INIT;
   
   if(cavium_debug_level > 2)
#ifndef MC2
      cavium_dump("dptr", microcode->data, microcode->data_size);
#else
      cavium_dump("dptr", microcode->data+40, microcode->data_size);
#endif

/* nplus change */
   if((nplus || ssl>0 || ipsec>0) && (pkp_dev->device_id != NPX_DEVICE) && (pkp_dev->device_id != N3_DEVICE))
      srq_idx = send_command(pkp_dev, &request, 0, BOOT_IDX, completion_address);
   else
      send_command(pkp_dev, &request, 0, BOOT_IDX, completion_address);
   ret = check_completion(pkp_dev, completion_address, 500, BOOT_IDX,srq_idx);
/* nplus change end */

   if (ret) 
   {
      cavium_error( "Error: %x in sending setup ucode request\n", ret);
      ret = 1;
      goto boot_setup_err;
   }

   ret = 0;

boot_setup_err:
   if (outbuffer)
   {
      cavium_unmap_kernel_buffer(pkp_dev,
                   betoh64(request.rptr), 8,
                   CAVIUM_PCI_DMA_BIDIRECTIONAL);
           /*kfree(out_buffer);*/
      cavium_free_dma((Uint8 *)outbuffer);
   }

   return ret;
}
#endif

/*
 * Intialize Encrypted master secret key and IV in the first 48 bytes of FSK.
 */
int
init_ms_key(cavium_device *pkp_dev,int ucode_idx)
{
   int ret = 0;
   Uint8 *out_buffer = NULL;
   Uint8 *in_buffer = NULL;
   Uint64 *completion_address;
   Request request;
   Cmd* strcmd = (Cmd*)&request;
   Uint16 km_size = 48;    /* key material size */
   Uint64 data_ptr = 0, recv_ptr= 0;
   Uint32 data_len = 0, recv_len= 0;
   int i=0,j=0;
   int rnd_count =1;
    MPRINTFLOW();
   
   strcmd->opcode = htobe16((0x1<<8) | MAJOR_OP_RANDOM_WRITE_CONTEXT);
   strcmd->size = htobe16(km_size);
   strcmd->param = htobe16(0);
   strcmd->dlen = htobe16(0);

   out_buffer = (Uint8 *)cavium_malloc_dma((km_size + 8 + ALIGNMENT), NULL);
   if(out_buffer == NULL) 
   {
     cavium_dbgprint( "unable to allocate out_buffer in init_ms_key.\n");
     ret = 1;
     goto ms_init_err;
    }
   data_len = 0;
   data_ptr = (Uint64)0;

   recv_len = km_size+8+ALIGNMENT;
   recv_ptr = (Uint64)cavium_map_kernel_buffer(pkp_dev,
                   out_buffer,
                   recv_len,
                   CAVIUM_PCI_DMA_BIDIRECTIONAL);
   if(!recv_ptr)	
   {
     cavium_error( "unable to map kernel buffer in init_ms_key \n");
     ret = 1;
     goto ms_init_err;
   }
   request.rptr = htobe64((recv_ptr+ALIGNMENT) & ALIGNMENT_MASK);
   request.dptr = htobe64(0);
   request.cptr = htobe64(0);

   completion_address = (Uint64 *)(((ptrlong)out_buffer + km_size + ALIGNMENT) & ALIGNMENT_MASK);
/* send Random Request to all the cores */
 if (!n3_vf_driver) {
  if(pkp_dev->device_id ==N3_DEVICE)
    if(vf_count) {
      rnd_count = 0;
      if (ssl == 0)
      rnd_count = pkp_dev->max_cores;
      else if (ssl > -1 )
       rnd_count += ssl;
      if (ipsec == 0)
      rnd_count = pkp_dev->max_cores;
      else if (ipsec > -1)
       rnd_count += ipsec;
    }

  cavium_dbgprint("%s(): rnd_count: %d\n", __func__, rnd_count);
   if (ssl < 0 && ipsec > -1)
       ucode_idx++; //Only IPSEC selected.
   for(j=0;j<rnd_count;j++){
    *completion_address = COMPLETION_CODE_INIT;
    if(ssl > -1 && j == ssl) {
      ucode_idx++; //Both SSL and IPSEC selected.
       cavium_dbgprint("incrementing ucode_idx: %d\n", ucode_idx);
    }
    send_command(pkp_dev, &request, j, ucode_idx, completion_address);
    i=0;
    while(*(completion_address) == COMPLETION_CODE_INIT){
     cavium_mdelay(2);
     i++;
     if(i>500)
     { 
       printk (KERN_CRIT "core: %d failed ipsec: %d ssl: %d rnd_count: %d\n", j, ipsec, ssl, rnd_count);
       ret = ERR_REQ_TIMEOUT;
       break;
    }
     cavium_invalidate_cache(pkp_dev, COMPLETION_CODE_SIZE, completion_address, completion_address,CAVIUM_PCI_DMA_BIDIRECTIONAL);
   } 
  }
   if(ipsec>-1 && vf_count) {
       ucode_idx--;
       cavium_dbgprint(" decrementing ucode_idx: %d\n", ucode_idx);
   }
   } else {
    *completion_address = COMPLETION_CODE_INIT;
    send_command(pkp_dev, &request, 0, ucode_idx, completion_address);
    i=0;
    while(*(completion_address) == COMPLETION_CODE_INIT){
     cavium_mdelay(2);
     i++;
     if(i>500)
     { 
       ret = ERR_REQ_TIMEOUT;
       break;
    }
     cavium_invalidate_cache(pkp_dev, COMPLETION_CODE_SIZE, completion_address, completion_address,CAVIUM_PCI_DMA_BIDIRECTIONAL);
   } 
  }
   if (ret) 
   {
      cavium_error("Error: %x out while sending random request in init_ms_key.\n", ret);
      ret=1;
      goto ms_init_err;
   }

   if(ssl < 0) { /* below steps not required for only ipsec case */
     ret = 0;
     goto ms_init_err;
   }


   /* now we have random number in out_buffer.
      Copy 48 bytes to the begining of the FSK memory. Incase of multicards, we use the random bytes generated by the first device for all devices*/

  if(first_round)
  {
     cavium_memcpy(&global_rnd[0], out_buffer, 48+ALIGNMENT);
     first_round = 0;
  }
  else
  {
    cavium_memcpy(out_buffer, &global_rnd[0], 48+ALIGNMENT);
  }

   cavium_dbgprint( "Sending WriteEpci request in init_ms_key.\n");

   /* Here starts WriteEpci call */
   strcmd->opcode= htobe16((0x0<<8) | MAJOR_OP_RANDOM_WRITE_CONTEXT);
   strcmd->size  = htobe16(0);
   strcmd->param = htobe16(0x0);
   strcmd->dlen  = htobe16(km_size + 8);
   in_buffer = (Uint8 *)cavium_malloc_dma((km_size + 8 + ALIGNMENT), NULL);
   if (in_buffer == NULL) 
   {
     cavium_print( "unable to allocate in_buffer in init_ms_key.\n");
     ret = 1;
     goto ms_init_err;
   }
   cavium_unmap_kernel_buffer(pkp_dev,
                    recv_ptr, recv_len,
                    CAVIUM_PCI_DMA_BIDIRECTIONAL);

   cavium_memset(in_buffer, 0, 48 + ALIGNMENT);
   cavium_memcpy((Uint8 *)(((ptrlong)in_buffer + 8 + ALIGNMENT) & ALIGNMENT_MASK), out_buffer, km_size);       /* now first 8 bytes have zeros, our key handle.*/

  data_len = km_size+8+ALIGNMENT;
  recv_len = 8+ALIGNMENT;
  data_ptr = (Uint64)cavium_map_kernel_buffer(pkp_dev,
                   in_buffer, data_len,
                   CAVIUM_PCI_DMA_BIDIRECTIONAL);
   if(!data_ptr)
   {
     cavium_error( "unable to map kernel buffer in init_ms_key \n");
     ret = 1;
     goto ms_init_err;
   }
  recv_ptr = (Uint64)cavium_map_kernel_buffer(pkp_dev,
                   out_buffer, recv_len,
                   CAVIUM_PCI_DMA_BIDIRECTIONAL);
   if(!recv_ptr)
   {
     cavium_error( "unable to map kernel buffer in init_ms_key \n");
     ret = 1;
     goto ms_init_err;
   }

   request.dptr = htobe64((data_ptr+ALIGNMENT) & ALIGNMENT_MASK);
   request.rptr = htobe64((recv_ptr+ALIGNMENT) & ALIGNMENT_MASK);
   request.cptr = htobe64(0);

   completion_address = (Uint64 *)(((ptrlong)out_buffer + ALIGNMENT) & ALIGNMENT_MASK);
   *completion_address = COMPLETION_CODE_INIT;
   send_command(pkp_dev, &request, 0, ucode_idx, completion_address);
   i=0;
   while(*(completion_address) == COMPLETION_CODE_INIT){
    cavium_mdelay(2);
    i++;
    if(i>500)
    { 
       ret = ERR_REQ_TIMEOUT;
       break;
    }
     cavium_invalidate_cache(pkp_dev, COMPLETION_CODE_SIZE, completion_address, completion_address,CAVIUM_PCI_DMA_BIDIRECTIONAL);
   }
   if(ret) 
   {
      cavium_error( "Error: %x while sending WriteEpci request in init_ms_key.\n", ret);
      ret=1;
      goto ms_init_err;
   }

   cavium_dbgprint( "Encrypted Master Secret successfully initialized.\n");

   ret =0;

ms_init_err:
   if(out_buffer)
   {
       cavium_unmap_kernel_buffer(pkp_dev,
                    recv_ptr, recv_len,
                    CAVIUM_PCI_DMA_BIDIRECTIONAL);
       cavium_free_dma((Uint8 *)out_buffer);
   }
   if(in_buffer)
   {
        cavium_unmap_kernel_buffer(pkp_dev,
                    data_ptr, data_len,
                    CAVIUM_PCI_DMA_BIDIRECTIONAL);
        cavium_free_dma((Uint8 *)in_buffer);
   }
   return ret;
}/* init_ms_key */



/*
 * boot init
 */
static int
pkp_boot_init(cavium_device *pkp_dev) 
{
   struct MICROCODE *microcode;
   Request request;
   Cmd* strcmd = (Cmd*)&request;
   volatile Uint64 *completion_address;
   Uint8 *outbuffer = NULL;
   int ret, srq_idx = -1;

   MPRINTFLOW();
   microcode = get_microcode(pkp_dev, (nplus||ssl>0||ipsec>0)?BOOT_IDX:CODE_TYPE_BOOT);
   if (microcode == NULL) 
   {
      cavium_print(  "Unable to get microcode struct in boot init\n");
      ret=1;
      goto boot_init_err;
   }

   outbuffer = cavium_malloc_dma(8 +ALIGNMENT, NULL);

   if (outbuffer == NULL) 
   {
      cavium_print( "unable to allocate out_buffer in sending boot init request\n");
      ret=1;
      goto boot_init_err;
   }

   strcmd->opcode = htobe16(OP_BOOT_INIT);
   strcmd->size   = 0;
   strcmd->param  = 0;


#ifdef MC2
   strcmd->param = htobe16(SCRATCHPAD_SIZE);
   strcmd->dlen  = htobe16(microcode->data_size + 40);
#else
   strcmd->dlen  = htobe16(microcode->data_size >> 3);
#endif


#ifdef MC2
   /* Format the first 40 bytes, with WD_TIMEOUT, SPI_KEY, CTX window base,
    * Error address, scratchpad base & CTP base
    */
   *((Uint32 *)microcode->data) = htobe32(0xffffffff);
   *((Uint32 *)(microcode->data+4)) = htobe32(0);
   *((Uint64 *)(microcode->data+8)) = htobe64(0);

#ifndef MCODE_LARGE_DUMP
   cavium_memset(pkp_dev->error_val, 0xff, sizeof(Uint64));
#else
   cavium_memset(pkp_dev->error_val, 0xff, 2*1024);
#endif
   
   *((Uint64 *)(microcode->data+16)) = htobe64((Uint64)(pkp_dev->error_val_busaddr));
   *((Uint64 *)(microcode->data+24)) = htobe64((Uint64)(pkp_dev->scratchpad_base_busaddr));

#endif
   
   cavium_dbgprint("Microcode data size %d dlen %x\n", 
                   microcode->data_size, strcmd->dlen);
   cavium_dbgprint("Microcode data @ virt %p bus: 0x%llx\n",
                   microcode->data, CAST64(microcode->data_dma_addr));
   request.dptr = htobe64(microcode->data_dma_addr);

   completion_address = (Uint64 *)(((ptrlong)outbuffer + ALIGNMENT) & ALIGNMENT_MASK);

   *completion_address = COMPLETION_CODE_INIT;

 request.rptr = (Uint64)cavium_map_kernel_buffer(pkp_dev,
                   (((ptrlong)outbuffer + ALIGNMENT) & ALIGNMENT_MASK),
                   8,
                   CAVIUM_PCI_DMA_BIDIRECTIONAL);

   if(! request.rptr)
   {
     cavium_error("unable to map kernel buffer in sending boot init request\n");
     ret=1;
     goto boot_init_err;
   }
   request.rptr = htobe64(request.rptr);
   request.cptr = htobe64(0);


   if(cavium_debug_level > 2)
#ifndef MC2
      cavium_dump("dptr", microcode->data, microcode->data_size);
#else
      cavium_dump("dptr", microcode->data, microcode->data_size+40);
#endif

/* nplus change */   
   if((nplus || ssl>0 || ipsec>0) && pkp_dev->device_id != NPX_DEVICE && pkp_dev->device_id != N3_DEVICE)
      srq_idx = send_command(pkp_dev, &request, 0,BOOT_IDX, (Uint64 *)(ptrlong)completion_address);
   else
      send_command(pkp_dev, &request, 0, BOOT_IDX, (Uint64 *)(ptrlong)completion_address);

   ret = check_completion(pkp_dev, completion_address, 500, BOOT_IDX,srq_idx);
/* nplus change end */   

   if(ret) 
   {
      cavium_error("Error : %x in sending boot init request.\n", ret);
      ret=1;
      goto boot_init_err;
   }
   ret = 0;

boot_init_err:
   if (outbuffer)
   {
     cavium_unmap_kernel_buffer(pkp_dev,
                   betoh64(request.rptr), 8,
                   CAVIUM_PCI_DMA_BIDIRECTIONAL);
      cavium_free_dma(outbuffer);
   }

   return ret;
}
             


Uint8  pf_vf[9] = {0, 4, 3, 0, 2, 0, 0, 0, 1};

/* 
 * load microcode, do core discovery, send init requests.
 */
int
do_init(cavium_device *pdev)
{
   int i,ret=0;
   Uint32 dwval=0,uen=0, imr =0,fexec =0, isr=0;
   int id;
   MPRINTFLOW();

      /* Step -1: reset command queues */
      for(i=0; i < pdev->max_queues; i++)
      {
         reset_command_queue(pdev, i);
      }

   /* Step 0: disable all units */
   cavium_udelay(10);
   pdev->cavfns.disable_request_unit(pdev);
   cavium_udelay(10);
   if (!n3_vf_driver) {
   pdev->cavfns.disable_all_exec_units(pdev);
   cavium_udelay(10);

   /* Initialize the npx group list array */
   if((nplus || ssl > 0 || ipsec > 0) && pdev->device_id == NPX_DEVICE)
      init_npx_group_list();
   /* Load boot microcode */
   if(pdev->cavfns.load_microcode(pdev, (nplus||ssl>0||ipsec>0)?BOOT_IDX:CODE_TYPE_BOOT))
    
   {
      cavium_error("Error loading boot microcode\n");
      ret = ERR_INIT_FAILURE;
      goto do_init_err;
   }
   /* setup group mask . Now Set all into same group */
   if(pdev->device_id == N3_DEVICE){
     Uint32 new_core_grp_mask=0xffffffff;
         write_PKP_register(pdev,(pdev->CSRBASE_A+ N3_IQMQ_GRP0_EXECMSK_LO), new_core_grp_mask);
          cavium_udelay(10);
         write_PKP_register(pdev,(pdev->CSRBASE_A+ N3_IQMQ_GRP0_EXECMSK_LO+(Uint32)(1<<8)), new_core_grp_mask);
          cavium_udelay(10);
         write_PKP_register(pdev,(pdev->CSRBASE_A+ N3_IQMQ_GRP0_EXECMSK_LO+(Uint32)(2<<8)), new_core_grp_mask);
          cavium_udelay(10);
         write_PKP_register(pdev,(pdev->CSRBASE_A+ N3_IQMQ_GRP0_EXECMSK_LO+(Uint32)(3<<8)), new_core_grp_mask);
          cavium_udelay(10);
         write_PKP_register(pdev,(pdev->CSRBASE_A+ N3_IQMQ_GRP0_EXECMSK_LO+(Uint32)(4<<8)), new_core_grp_mask);
          cavium_udelay(10);
         write_PKP_register(pdev,(pdev->CSRBASE_A+ N3_IQMQ_GRP0_EXECMSK_LO+(Uint32)(5<<8)), new_core_grp_mask);
          cavium_udelay(10);
         write_PKP_register(pdev,(pdev->CSRBASE_A+ N3_IQMQ_GRP0_EXECMSK_LO+(Uint32)(6<<8)), new_core_grp_mask);
          cavium_udelay(10);
         write_PKP_register(pdev,(pdev->CSRBASE_A+ N3_IQMQ_GRP0_EXECMSK_LO+(Uint32)(7<<8)), new_core_grp_mask);
          cavium_udelay(10);
         write_PKP_register(pdev,(pdev->CSRBASE_A+ N3_IQMQ_GRP0_EXECMSK_HI), new_core_grp_mask);
          cavium_udelay(10);
         write_PKP_register(pdev,(pdev->CSRBASE_A+ N3_IQMQ_GRP0_EXECMSK_HI+(Uint32)(1<<8)), new_core_grp_mask);
          cavium_udelay(10);
         write_PKP_register(pdev,(pdev->CSRBASE_A+ N3_IQMQ_GRP0_EXECMSK_HI+(Uint32)(2<<8)), new_core_grp_mask);
          cavium_udelay(10);
         write_PKP_register(pdev,(pdev->CSRBASE_A+ N3_IQMQ_GRP0_EXECMSK_HI+(Uint32)(3<<8)), new_core_grp_mask);
          cavium_udelay(10);
         write_PKP_register(pdev,(pdev->CSRBASE_A+ N3_IQMQ_GRP0_EXECMSK_HI+(Uint32)(4<<8)), new_core_grp_mask);
          cavium_udelay(10);
         write_PKP_register(pdev,(pdev->CSRBASE_A+ N3_IQMQ_GRP0_EXECMSK_HI+(Uint32)(5<<8)), new_core_grp_mask);
          cavium_udelay(10);
         write_PKP_register(pdev,(pdev->CSRBASE_A+ N3_IQMQ_GRP0_EXECMSK_HI+(Uint32)(6<<8)), new_core_grp_mask);
          cavium_udelay(10);
         write_PKP_register(pdev,(pdev->CSRBASE_A+ N3_IQMQ_GRP0_EXECMSK_HI+(Uint32)(7<<8)), new_core_grp_mask);
          cavium_udelay(10);
   }
   } //!n3_vf_driver
   /* Step 1: enable request and boot cores */
   cavium_dbgprint("Enable request and boot cores\n");
   pdev->cavfns.enable_request_unit(pdev);
   cavium_udelay(10);      
   pdev->cavfns.enable_data_swap(pdev);
   cavium_udelay(10);
   pdev->cavfns.enable_rnd_entropy(pdev);    
   cavium_udelay(10);

   /* Step 2: Core discovery mechanism */
   cavium_dbgprint("Core Discovery Mechanism\n");
   /* Disable Interrupts */
   isr=0;
   imr=0;
   if(pdev->device_id == NPX_DEVICE){
       read_PKP_register(pdev,(pdev->CSRBASE_A + IMR_REG),&imr);
       cavium_udelay(10);
       write_PKP_register(pdev,(pdev->CSRBASE_A + IMR_REG),0);
       cavium_udelay(10);
       read_PKP_register(pdev,(pdev->CSRBASE_A + ISR_REG),&isr);
       cavium_udelay(10);
       write_PKP_register(pdev,(pdev->CSRBASE_A + ISR_REG),isr);

       /* read bist register */
      dwval=0;
      read_PKP_register(pdev,(pdev->CSRBASE_A + FAILING_EXEC_REG), &dwval);
      cavium_udelay(10);

      cavium_dbgprint("read %08x from FAILING_EXE_REG\n", dwval);

      dwval = ((~dwval) & 0xff) | 0xf0000000; /*keep request unit alive */
      cavium_dbgprint("Enabling Units : %08x \n",dwval);
      /* write unit enable to enable only good cores */
      cavium_udelay(10);
      write_PKP_register(pdev,(pdev->CSRBASE_A + UNIT_ENABLE), dwval);
      uen = dwval;
      cavium_udelay(10);
   
      /* check for ucode parity error*/
      dwval = 0;
      read_PKP_register(pdev,(pdev->CSRBASE_A + ISR_REG), &dwval);
      cavium_dbgprint("do_int : isr reg %x\n", dwval);
      if(dwval & 0x1) 
      {
        fexec=0;
        read_PKP_register(pdev, (pdev->CSRBASE_A + FAILING_EXEC_REG), &fexec);
        uen = uen ^ fexec;
        cavium_error("Ucode parity error. Failing exec: %08x\n",fexec);
      }

      /* check register file parity error */
      if(dwval & 0x2) 
      {
        /* read failing exec register */
        fexec=0;
        read_PKP_register(pdev, (pdev->CSRBASE_A + FAILING_EXEC_REG), &fexec);
        uen = uen ^ fexec;
        cavium_error( "register file parity error. Failing exec: %08x\n", fexec);
      }

      cavium_udelay(10);

      cavium_print("Write 0x%x into CORE ENABLE after Interrupt bits check\n", uen);
      /* Now enable all good cores */
      write_PKP_register(pdev, (pdev->CSRBASE_A + UNIT_ENABLE), uen);

      /* now enable interrupts */
      write_PKP_register(pdev, (pdev->CSRBASE_A + ISR_REG), dwval);
      write_PKP_register(pdev, (pdev->CSRBASE_A + IMR_REG), imr);


   }else if(pdev->device_id == N3_DEVICE && !n3_vf_driver)
   {
       write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_ISR_0),0);
       cavium_udelay(10);
       write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_ISR_1),0);
       cavium_udelay(10);
       write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_ISR_2),0);
       cavium_udelay(10);
       write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_ISR_3),0);
       cavium_udelay(10);
       write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_INT_EN_0),0);
       cavium_udelay(10);
       write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_INT_EN_1),0);
       cavium_udelay(10);
       write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_INT_EN_2),0);
       cavium_udelay(10);
       write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_INT_EN_3),0);
       cavium_udelay(10);
       write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_FINT_EN_0),0);
       cavium_udelay(10);
       write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_FINT_EN_1),0);
       cavium_udelay(10);
       write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_FINT_EN_2),0);
       cavium_udelay(10);
       write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_FINT_EN_3),0);
       cavium_udelay(10);
      /* Enable good cores */
       #if 0
      dwval=0;    
      read_PKP_register(pdev, (pdev->CSRBASE_A + N3_CORE_AVAIL_0) , &dwval);
      cavium_udelay(10);
      write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_EN_0),dwval);
      cavium_udelay(10);
      read_PKP_register(pdev, (pdev->CSRBASE_A + N3_CORE_AVAIL_1) , &dwval);
      cavium_udelay(10);
      write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_EN_1),dwval);
      cavium_udelay(10);
      read_PKP_register(pdev, (pdev->CSRBASE_A + N3_CORE_AVAIL_2) , &dwval);
      cavium_udelay(10);
      write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_EN_2),dwval);
      cavium_udelay(10);
      read_PKP_register(pdev, (pdev->CSRBASE_A + N3_CORE_AVAIL_3) , &dwval);
      cavium_udelay(10);
      write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_EN_3),dwval);
      cavium_udelay(10);
      read_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_ISR_0), &fexec);
      cavium_udelay(10);
      if(fexec & 0x7)
      {
        read_PKP_register(pdev, (pdev->CSRBASE_A + N3_CORE_AVAIL_0),&dwval);
        cavium_udelay(10);
        uen=dwval^(fexec>>16);
        write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_EN_0),uen);
        cavium_udelay(10);
      }
      read_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_ISR_1), &fexec);
      cavium_udelay(10);
      if(fexec & 0x7)
      {
        read_PKP_register(pdev, (pdev->CSRBASE_A + N3_CORE_AVAIL_1),&dwval);
        cavium_udelay(10);
        uen=dwval^(fexec>>16);
        write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_EN_1),uen);
        cavium_udelay(10);
      }
      read_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_ISR_2), &fexec);
      cavium_udelay(10);
      if(fexec & 0x7)
      {
        read_PKP_register(pdev, (pdev->CSRBASE_A + N3_CORE_AVAIL_2),&dwval);
        cavium_udelay(10);
        uen=dwval^(fexec>>16);
        write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_EN_2),uen);
        cavium_udelay(10);
      }
      read_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_ISR_2), &fexec);
      cavium_udelay(10);
      if(fexec & 0x7)
      {
        read_PKP_register(pdev, (pdev->CSRBASE_A + N3_CORE_AVAIL_3),&dwval);
        cavium_udelay(10);
        uen=dwval^(fexec>>16);
        write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_EN_3),uen);
        cavium_udelay(10);
      }
      #endif
   /* now enable interrupts */
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
   }
   /* now read all good cores */
   /* it will populate all good cores. pdev->uen */
   if (!n3_vf_driver) {
   dwval = pdev->cavfns.get_exec_units(pdev);
   if(dwval < (Uint32) pdev->max_cores) 
   {
      cavium_error("%d good cores found whereas this part requires %d cores\n",dwval,pdev->max_cores);
      ret = ERR_INIT_FAILURE;
      goto do_init_err;
   }
   } //!n3_vf_driver
   pdev->exec_units = pdev->max_cores;
   uen = get_exec_units_part(pdev);
   if(!uen) 
   {
     cavium_error("Couldn't find %d cores for current part\n",pdev->exec_units);
     ret = ERR_INIT_FAILURE;
     goto do_init_err;
   }

   /* check if we have got proper core mask */
   if(check_core_mask(pdev, uen)) 
   {
      cavium_error("Final core mask does not comply with the expected value(s).\n");
      ret = ERR_INIT_FAILURE;
      goto do_init_err;
   }

   cavium_print("UEN = 0x%x\n", uen);

   pdev->uen = uen;
   if (!n3_vf_driver) {
   pdev->boot_core_mask = get_first_available_core(MAX_CORES_NITROX, 
                     pdev->uen);
   cavium_print("Final Core Mask = 0x%08x\n", uen);

   cavium_print("Loaded Boot microcode\n");

   /*disable all cores, leave request unit at the present state */
   pdev->cavfns.disable_all_exec_units(pdev);
   cavium_dbgprint( "enabling boot core. %x\n",pdev->boot_core_mask);
   pdev->cavfns.enable_exec_units_from_mask(pdev, pdev->boot_core_mask);

   /* send boot init command */
   cavium_dbgprint( "sending boot init request\n");
   if (pkp_boot_init(pdev)) 
   {
      cavium_error( "Error sending boot_init command %d\n",i);
      ret = ERR_INIT_FAILURE;
      goto do_init_err;
   }
   /* We do this for each microcode that we intend to run. */
#ifndef LOAD_BOOT_ONLY
   for(i=1; i<MICROCODE_MAX - !nplus; i++)
   {
      if(pdev->microcode[i].code == NULL)
         continue;
      if(pkp_boot_setup_ucode(pdev, i))
      {
         cavium_error("Error sending boot_setup_ucode command\n");
         ret = ERR_INIT_FAILURE;
         goto do_init_err;
      }
   }
#endif
/*   cavium_dbgprint( "sending boot setup ucode command\n");
   if (pkp_boot_setup_ucode(pdev)) 
   {
      cavium_error( "Error sending boot_setup_ucode command\n");
      ret = ERR_INIT_FAILURE;
      goto do_init_err;
   }
   }*/

   /* disable boot unit. Not required anymore */
#ifndef LOAD_BOOT_ONLY 
   cavium_dbgprint( "Disabling boot core\n");
 // cavfns.disable_exec_units_from_mask(pdev, pdev->boot_core_mask);
 if(pdev->device_id == N3_DEVICE)
  disable_exec_masks_n3(pdev);
  pdev->cavfns.disable_all_exec_units(pdev);
#endif
   /* We dont enable the units now, but delay it till the IOCTL_CSP1_INIT_CODE
    * is made by the admin utility. The MS Key initialization, and random
    * number buffer fill, is also delayed till then.
    */
   } //!n3_vf_driver
   /* We add the cores to the list of free core */
   if (nplus || ssl>0 || ipsec>0)
   {
   cavium_dbgprint("pdev->uen: 0x%x\n", pdev->uen);
   if(pdev->device_id == NPX_DEVICE)
      pdev->microcode[FREE_IDX].core_grp  = get_next_npx_group();

   for(id=0;id<MAX_CORES_NITROX;id++)
   {
      cavium_dbgprint("id: %d\n", id);
      if(pdev->uen & (1<<id))
      {
         pdev->cores[id].next_id = pdev->microcode[FREE_IDX].core_id;
         pdev->microcode[FREE_IDX].core_id = id;
         pdev->cores[id].ucode_idx = FREE_IDX;
      }
   }

   ret = 0;
   /* return with success */
   goto do_init_err;
  }
   else 
   {
#ifndef LOAD_BOOT_ONLY
   /* load mainline microcode */
   if(pdev->cavfns.load_microcode(pdev, CODE_TYPE_MAINLINE)) 
   {
      cavium_error("Error loading mainline microcode\n");
      ret = ERR_INIT_FAILURE;
      goto do_init_err;
   }
#endif
   /* enable only part number specific cores*/
  if (!n3_vf_driver)
   pdev->cavfns.enable_exec_units(pdev);
 if((pdev->device_id == N3_DEVICE) && !n3_vf_driver)
      enable_exec_masks_n3(pdev);
   
   cavium_udelay(10);
   cavium_print( "Loaded Main microcode\n");
   /* 
    * Now initialize encrypted master secret key and IV in the 
    * first 48 bytes of FSK 
    */
   
   if (!n3_vf_driver) { 
   if(init_ms_key(pdev, 1))
   //if((nplus || ssl>=0) && init_ms_key(pdev, 1))
   {
           cavium_print( "Couldnot initialize encrypted master secret key and IV.\n");
           ret = ERR_INIT_FAILURE;
           goto do_init_err;
   }
   }
  boot_time=0;
  if(pdev->device_id == N3_DEVICE && !n3_vf_driver)
      enable_exec_masks_n3(pdev);
  pdev->enable=1;

   /* set doobell thresholds for each queue */
   for(i=0;i<pdev->max_queues;i++)
   {
      lock_command_queue(pdev, i);
      if(i==0)
         pdev->door_bell_threshold[i] =1;
      else
         pdev->door_bell_threshold[i] = DOOR_BELL_THRESHOLD;
      unlock_command_queue(pdev, i);
   }   
   ret=0;
   cavium_print("Loading of Microcodes successful\n");
#ifdef PROCFS_SUPPORT
   cavium_print("Check /proc/cavium directory for more information\n");
#endif
   }
   if(pdev->device_id == N3_DEVICE && !n3_vf_driver){
       if(vf_count > 0){
        pdev->cavfns.disable_request_unit(pdev);
        enable_exec_masks_n3(pdev);
	boot_time=1;
        pci_enable_sriov(pdev->dev, vf_count);
	read_PKP_register(pdev, (pdev->CSRBASE_A + N3_CMD_REG), &dwval);
	dwval |= (pf_vf[vf_count/8] << 24);
	write_PKP_register(pdev, (pdev->CSRBASE_A + N3_CMD_REG), dwval);
      }
       read_PCI_register(pdev, N3_PCIE_DEV_CTRL, &dwval);
       dwval&=~((Uint32)0x2000);
       dwval|=((Uint32)0x4100);
       write_PCI_register(pdev, N3_PCIE_DEV_CTRL, dwval);
   }
  if(pdev->device_id == N3_DEVICE && !n3_vf_driver)
  {
     dwval=get_core_frequency(pdev);
     cavium_print("\nCore Frequency %d MHz\n",dwval);
  }
  
  
do_init_err:
  if(pdev->device_id==NPX_DEVICE){      
   if(ret == 0) {
      /* Set all cores to the same group */
      write_PKP_register(pdev, (pdev->CSRBASE_A + REG_EXEC_GROUP), 0x11111111);
      read_PKP_register(pdev, (pdev->CSRBASE_A + REG_EXEC_GROUP), &dwval);
      cavium_print("All cores joined to group 0,REG_EXEC_GRP: 0x%08x\n", dwval);
   }
  if(pdev->px_flag!=CN15XX)
   {
       cavium_print("Additional setup for CN1600\n");
       
       read_PCI_register(pdev, 0x78, &dwval);
       cavium_print("Config: Device Control Reg (offset 0x78): 0x%08x\n",dwval);
       if(dwval & 0x000f0000) {
           cavium_print("PCI-E Link error detected: 0x%08x\n",
                        dwval & 0x000f0000);
       }
       dwval |= 0xf;  /* Enable Link error reporting */
       dwval |= 0x00000800;  /* Enable NO Snoop */
       dwval &= 0xffffffef;  /* Disable Relaxed Ordering. */

       cavium_dbgprint("Enabling PCI-E error reporting..\n");
       cavium_dbgprint("Writing  0x%08x to config[0x78]\n", dwval);
      write_PCI_register(pdev, 0x78, dwval); 
   }
  
}
   return ret;

}/* do_init*/

		



/*------------------------------------------------------------------------------
 * 
 *  Device initialization.
 *  This function initializes the board. 
 *
 *----------------------------------------------------------------------------*/

int pkp_init_board(cavium_device *pdev)
{

   Uint32 dwval;

   MPRINTFLOW();
   pdev->cavfns.setup_request_queues(pdev);

   cavium_udelay(10);
 if(pdev->device_id==NPX_DEVICE){
   /* clear ISR register */
    dwval = 0x00007fff;
    write_PKP_register(pdev,(pdev->CSRBASE_A+ISR_REG), dwval);
    cavium_udelay(10);
   /* clear pci error reg */
   dwval = 0x0007ffff;
   write_PKP_register(pdev,(pdev->CSRBASE_A+PCI_ERR_REG), dwval);
   }else if(pdev->device_id == N3_DEVICE)
   {
     dwval = 0x00;
     write_PKP_register(pdev,(pdev->CSRBASE_A+N3_CORE_ISR_0), dwval);
     cavium_udelay(10);
     write_PKP_register(pdev,(pdev->CSRBASE_A+N3_CORE_ISR_1), dwval);
     cavium_udelay(10);
     write_PKP_register(pdev,(pdev->CSRBASE_A+N3_CORE_ISR_2), dwval);
     cavium_udelay(10);
     write_PKP_register(pdev,(pdev->CSRBASE_A+N3_CORE_ISR_3), dwval);
     cavium_udelay(10);
     dwval=0x011F3FFF;
     write_PKP_register(pdev,(pdev->CSRBASE_A+HSI_ERR_ENAB_SET), dwval);
   }

   cavium_udelay(10);
 if(pdev->device_id == NPX_DEVICE && pdev->px_flag == CN15XX){
   set_PCI_cache_line(pdev);
   set_PCIX_split_transactions(pdev);
   cavium_udelay(10);
   /* Disable Master Latency Timer */
   write_PCI_register(pdev, 0x40, 1);
 }

     
   return 0;

}/*pkp_init_board*/



/*
 * load microcode
 */
int 
load_microcode_px(cavium_device *pdev, int type)
{
   Uint32 i,size,instruction;
   struct MICROCODE * microcode;
   Uint8 *code;
   
    MPRINTFLOW();
   size=0;
   if(type > MICROCODE_MAX || type < 0)
      return 1;

   microcode = get_microcode(pdev, (Uint8)type);
   if(microcode == NULL)
   {
      cavium_error("Unable to get microcode (%d)\n", type);
      return 1;
   }

   code = microcode->code;
   size = microcode->code_size;

   cavium_dbgprint("microcode type=%d, code size=%d\n", type, size);
   if(!code)
      return 1;

   /* For NPLUS mode microcode load verification, core on which
    * microcode is being loaded has to be known. In non-NPLus mode
    * code below, it is always assumed to be core 0. In NPLus that 
    * might not be true. So here I will resort to good old microcode
    * load procedure.
    */
   if (nplus || ssl > 0 || ipsec > 0) 
   {
      for (i=0; i<size/4; i++)
      {
         instruction = ntohl((Uint32)*((Uint32*)code+i));

         write_PKP_register(pdev,(pdev->CSRBASE_A+UCODE_LOAD), instruction);
         cavium_udelay(50);
      }
   }


   else 
   {
        write_PKP_register(pdev,(pdev->CSRBASE_A + DEBUG_REG), 0xf);
         for (i=0; i<size/4; i++)
         {
            Uint32 debug_val;

            instruction = betoh32((Uint32)*((Uint32*)code+i));

            /* write it once */
            write_PKP_register(pdev,(pdev->CSRBASE_A + UCODE_LOAD),instruction);
            cavium_udelay(50);

            /* write it once more */
            write_PKP_register(pdev,(pdev->CSRBASE_A + UCODE_LOAD),instruction);
            cavium_udelay(50);
            /* read debug register */
            debug_val=0;
            read_PKP_register(pdev,(pdev->CSRBASE_A + DEBUG_REG), &debug_val);
            debug_val >>= 12;

            debug_val &= 0xffff;
            instruction &= 0xffff;

            if(debug_val != instruction)
            {
               cavium_error("Ucode load failure: %d: (actual=)0x%x, (debug=)0x%x\n", i, instruction, debug_val);
               return 1;
            }
         }
   }
   return 0;
}


int 
load_microcode_n3(cavium_device *pdev, int type)
{
  if (!n3_vf_driver) {
   Uint32 i,size,instruction;
   struct MICROCODE * microcode;
   Uint8 *code;
   
    MPRINTFLOW();
   size=0;
   if(type > MICROCODE_MAX || type < 0)
      return 1;

   microcode = get_microcode(pdev, (Uint8)type);
   if(microcode == NULL)
   {
      cavium_error("Unable to get microcode (%d)\n", type);
      return 1;
   }

   code = microcode->code;
   size = microcode->code_size;
   cavium_dbgprint("microcode type=%d, code size=%d\n", type, size);
   if(!code)
      return 1;

   /* For NPLUS mode microcode load verification, core on which
    * microcode is being loaded has to be known. In non-NPLus mode
    * code below, it is always assumed to be core 0. In NPLus that 
    * might not be true. So here I will resort to good old microcode
    * load procedure.
    */
   if (nplus || ssl > 0 || ipsec > 0) 
   {
      for (i=0; i<size/4; i++)
      {
         instruction = ntohl((Uint32)*((Uint32*)code+i));

         write_PKP_register(pdev,(pdev->CSRBASE_A+N3_UCODE_LOAD), instruction);
         cavium_udelay(50);
      }
   }


   else 
   {
        write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_DBG_CTRL_0), 0xf0000);
        write_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_DBG_CTRL_1), 0xf0000);
         for (i=0; i<size/4; i++)
         {
            Uint32 debug_val1;
            Uint32 debug_val2;

            instruction = betoh32((Uint32)*((Uint32*)code+i));

            /* write it once */
            write_PKP_register(pdev,(pdev->CSRBASE_A + N3_UCODE_LOAD),instruction);
            cavium_udelay(50);

            /* write it once more */
            write_PKP_register(pdev,(pdev->CSRBASE_A + N3_UCODE_LOAD),instruction);
            cavium_udelay(50);
            /* read debug register */
            debug_val1=0;
            read_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_DBG_DATA_0), &debug_val1);
            debug_val2=0;
            read_PKP_register(pdev,(pdev->CSRBASE_A + N3_CORE_DBG_DATA_1), &debug_val2);
            debug_val1 &= 0xffff;
            debug_val2 &= 0xffff;

            instruction &= 0xffff;

            if(debug_val1 != instruction || debug_val2 != instruction)
            {
               cavium_error("Ucode load failure: %d: (actual=)0x%x, (debug1=)0x%x (debug2=)0x%x\n", i, instruction, debug_val1,debug_val2);
               return 1;
            }
         }
   }
  }
   return 0;
}

/*
 * Send initialization requests
 */

int send_init_request(cavium_device *pdev)
{
   Uint32 i;
   Uint8 *command;
   Request request;
   Cmd *strcmd = (Cmd*)&request;
   struct MICROCODE *microcode;
   Uint8 *cst;

   MPRINTFLOW();
   microcode = get_microcode(pdev, CODE_TYPE_MAINLINE);

   if(microcode == NULL)
      return 1;

   if(microcode->data_size)
   {
      cst = (Uint8 *)cavium_malloc_dma(microcode->data_size + ALIGNMENT, NULL);

      if(cst == NULL)
         return 1;

      cavium_memcpy((Uint8 *)(((ptrlong)cst + ALIGNMENT) & ALIGNMENT_MASK), microcode->data, microcode->data_size);

      strcmd->opcode= 0;
      strcmd->size  = 0;
      strcmd->param = 0;
      strcmd->dlen  = (Uint16)microcode->data_size/8;

      strcmd->opcode  = htobe16(strcmd->opcode);
      strcmd->size    = htobe16(strcmd->size);
      strcmd->param   = htobe16(strcmd->param);
      strcmd->dlen    = htobe16(strcmd->dlen);


      request.dptr = (Uint64)cavium_map_kernel_buffer(pdev,
                      (((ptrlong)cst + ALIGNMENT) & ALIGNMENT_MASK),
                      microcode->data_size,
                      CAVIUM_PCI_DMA_BIDIRECTIONAL);


      request.rptr = 0;
      request.cptr = 0;
   
      request.dptr = htobe64(request.dptr);
 
      lock_command_queue(pdev, 0);
      cavium_dbgprint("send_init: sending %d init requests\n", pdev->exec_units); 
      for (i=0;i <pdev->exec_units; i++)
      { 
         command = (Uint8 *)pdev->command_queue_front[0];      
         cavium_memcpy(command, (Uint8 *)&request,32);
         ring_door_bell(pdev, 0, 1);
         cavium_udelay(50);
         inc_front_command_queue(pdev, 0);
      }

      unlock_command_queue(pdev, 0);

      cavium_unmap_kernel_buffer(pdev,
                      betoh64(request.dptr),microcode->data_size,
                      CAVIUM_PCI_DMA_BIDIRECTIONAL);

      cavium_free_dma(cst);
   }
   else
      cavium_print("send_init_requests: No init to send.\n");
 
   return 0; 
}

int cavium_devres_init(cavium_device *pdev)
{
   int ret = 0;
   cavium_general_init_status status = NONE_SUCCESS;   
   status = NONE_SUCCESS;
   MPRINTFLOW();

   /* Initialize key memory chunks */
   if (nplus || ssl>=0)
   {
     cavium_dbgprint("cavium_devres_init:init key memory.\n");
     if (init_key_memory(pdev)) 
     {
       ret = ERR_MEMORY_ALLOC_FAILURE;
       goto init_devres_error;
     }
     status = INIT_KEY_MEMORY_SUCCESS;
   }
   cavium_dbgprint("cavium_devres_init:init completion dma free list.\n");
   return ret;

init_devres_error:
    switch (status)
    {
        case INIT_KEY_MEMORY_SUCCESS:
        {
       	  if (nplus || ssl>=0) cleanup_key_memory(pdev);
        }
	default: break;
    }
    return ret;
}

int cavium_devres_cleanup(cavium_device* pdev)
{
   cavium_dbgprint("cavium_devres_cleanup: entering\n");


//#ifdef SSL
   if (ssl==0) 
       cleanup_key_memory(pdev);
//#endif
      cavium_dbgprint("cavium_devres_cleanup: after free_buffer_pool\n");
      {
          Uint8 j = 0;
          for(j=0; j< MICROCODE_MAX-!nplus; j++)
          {
             if(pdev->microcode[j].data)
             {
           
#ifdef MC2
                  cavium_free_nc_dma(pdev, 
                                pdev->microcode[j].data_size+40,
                                pdev->microcode[j].data,
                                pdev->microcode[j].data_dma_addr);                
#else
                  cavium_free_nc_dma(pdev, 
                                pdev->microcode[j].data_size,
                                pdev->microcode[j].data,
                                pdev->microcode[j].data_dma_addr);                
#endif           
                  pdev->microcode[j].data=NULL;
                  pdev->microcode[j].data_size=0;
                  pdev->microcode[j].data_dma_addr=0;
             }
          }
      }

   cavium_dbgprint("cavium_devres_cleanup: returning\n");

   return 0;
}
	

/*
 * $Id: init_cfg.c,v 1.37 2011/05/11 14:34:12 tghoriparti Exp $
 * $Log: init_cfg.c,v $
 * Revision 1.37  2011/05/11 14:34:12  tghoriparti
 * FreeBSD porting for SDK 4.0
 *
 * Revision 1.36  2009/09/09 11:26:19  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.35  2009/07/15 10:32:22  aravikumar
 * Change to use same random number for all devices to initialize encrypted master secret key in init_ms_key
 *
 * Revision 1.34  2009/05/11 09:32:15  jrana
 * Done type casting on some variables to remove compilation errrors for windows.
 *
 * Revision 1.33  2008/12/22 05:42:10  jrana
 *  COUNTERS and INTERRUPT COALEASCING ADDED
 *
 * Revision 1.32  2008/12/16 12:04:42  jsrikanth
 * Added Common driver and Multi-Card Changes for FreeBSD
 *
 * Revision 1.31  2008/11/26 10:23:50  ysandeep
 * corrected a spelling mistake
 *
 * Revision 1.30  2008/11/06 09:09:20  ysandeep
 * Removed PX_PLUS
 *
 * Revision 1.29  2008/10/24 06:07:24  ysandeep
 * Key memory support added for NPLUS
 *
 * Revision 1.28  2008/10/15 08:03:39  ysandeep
 * Multicard support for NPLUS added.
 *
 * Revision 1.27  2008/09/30 13:15:17  jsrikanth
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
 * Revision 1.26  2008/07/18 05:53:20  aramesh
 * px_flag is set.
 *
 * Revision 1.25  2008/07/03 05:04:37  aramesh
 * deleted unwanted comments.
 *
 * Revision 1.24  2008/07/02 12:35:26  aramesh
 * deleted part number and corresponding flags.
 *
 * Revision 1.23  2008/05/15 08:49:52  sgadam
 * - MSI hang issue fixed
 *
 * Revision 1.22  2008/02/22 10:17:12  aramesh
 * N1_SANITY is set always.
 *
 * Revision 1.21  2008/02/14 05:37:35  kchunduri
 * --remove CN1600 dependency.
 *
 * Revision 1.20  2007/11/19 11:11:55  lpathy
 * ported to 64 bit windows.
 *
 * Revision 1.19  2007/07/31 14:08:05  tghoriparti
 * changes to cavium_common_cleanup revoked
 *
 * Revision 1.18  2007/07/31 10:11:08  tghoriparti
 * N1 related changes done
 *
 * Revision 1.17  2007/07/24 12:50:13  kchunduri
 * --defined new init functions.This is required for multi-card support in FreeBSD.
 *
 * Revision 1.16  2007/07/06 13:01:38  tghoriparti
 * command queues are reset before loading microcodes
 *
 * Revision 1.15  2007/06/11 13:41:07  tghoriparti
 * cavium_mmap_kernel_buffers return values handled properly when failed.
 *
 * Revision 1.14  2007/06/06 08:51:14  rkumar
 * Changed C++ style comments to C comments
 *
 * Revision 1.13  2007/05/04 10:45:35  kchunduri
 * fix compiler warning on FreeBSD.
 *
 * Revision 1.12  2007/05/01 05:20:43  kchunduri
 * * replaced pci_write_config_dword/pci_read_config_dword API with write_PCI_register/read_PCI_register OSI calls
 *
 * Revision 1.11  2007/04/04 21:50:58  panicker
 * * Added support for CN1600
 * * Error reporting is enabled for CN1600
 *
 * Revision 1.10  2007/03/08 20:43:33  panicker
 * * NPLUS mode changes. pre-release
 * * NitroxPX now supports N1-style NPLUS operation.
 * * Native PX mode PLUS operations are enabled only if PX_PLUS flag is enabled
 *
 * Revision 1.9  2007/03/06 03:09:28  panicker
 * * PX will use the same core id lookup mechanism as N1.
 * * send_command(), init_ms_key() uses same prototype as N1 for PX.
 * * check_completion() uses N1-nonNPLUS mode for NitroxPX NPLUS mode(PX_PLUS in the future)
 * * init_npx_group_list() called in do_init for PX.
 * * reg_exec register setting at end of do_init().
 *
 * Revision 1.8  2007/02/21 23:30:52  panicker
 * * Not all config registers need to be written by us now.
 * * boot init command send completion check after a small delay.
 *
 * Revision 1.7  2007/02/20 22:53:41  panicker
 * * print modified
 *
 * Revision 1.6  2007/02/02 02:32:55  panicker
 * * Core enable bits are different for PX
 * * door_addr is unsigned long now
 * * do_pci_write_config() to set config reg values for PX
 *
 * Revision 1.5  2007/01/16 02:20:26  panicker
 * * scratchpad is required for MC2 (even in PX)
 * * the ctp base was being sent in data (constants) for all MC2
 *   even in non-NPLUS mode. now ctp base will be sent only for
 *   MC2+NPLUS & !PX.
 *
 * Revision 1.4  2007/01/13 03:17:27  panicker
 * * compilation warnings fixed.
 * * scratchpad & ctp base address are not passed in pkp_boot_init() data buffer
 *   to cores in PX.
 *
 * Revision 1.3  2007/01/11 02:08:00  panicker
 *    - load_microcode()
 *      * the default NPLUS mode is not used for NITROX_PX.
 *      * NITROX_PX uses the non-1230 mode.
 *    - cavium_init()
 *      * in NPLUS mode initialization, core_id & use_count not used for PX;
 *        code & data is;
 *      * MC2 mode stp & scratchpad not used for PX, error val init is.
 *      * init_error - free ctp and scratchpad only if !(NITROX_PX).
 *    - cavium_cleanup()
 *      * MC2 mode stp & scratchpad not used for PX
 *    - do_init()
 *      * after microcode load, use NPLUS mode for exit but the pdev->cores
 *        initialization is skipped for PX.
 *    - pkp_boot_setup_code()
 *      * use NPLUS format function call; send_command in non-NPLUS mode.
 *    - init_ms_key()
 *      * use the non-NPLUS format in PX; send_command non-NPLUS
 *
 * Revision 1.2  2007/01/09 22:27:59  panicker
 * * REG_EXEC_GROUP register set to 0x11111111 for non-NPLUS mode.
 *
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.45  2006/09/25 10:11:31  ksnaren
 * Fixed comile errors for linux 2.4.18
 *
 * Revision 1.43  2006/05/17 04:20:15  kchunduri
 * --removed debug statements
 *
 * Revision 1.42  2006/05/16 09:28:36  kchunduri
 * --support for Dynamic DMA mapping instead of virt_to_phys
 *
 * Revision 1.41  2006/02/01 14:10:27  pyelgar
 *    - Fixed compilation warning.
 *
 * Revision 1.40  2006/01/19 09:48:08  sgadam
 * - IPsec 2.6.11 changes
 *
 * Revision 1.39  2005/12/07 04:50:59  kanantha
 * modified to support both 32 and 64 bit versions
 *
 * Revision 1.38  2005/11/28 05:40:43  kanantha
 * Removed compilation warnings for 64 bit CN1010
 *
 * Revision 1.37  2005/11/17 13:31:09  kanantha
 * Updating with the 64 bit modifications, with proper matching of data types
 *
 * Revision 1.36  2005/10/13 09:24:19  ksnaren
 * fixed compile warnings
 *
 * Revision 1.35  2005/10/05 07:38:41  ksadasivuni
 * - cleanup_pending_lists() was not being called in cavium_general_cleanup().
 *   It is being called now. some spin locks are destroyed here which is
 *   required for FreeBSD 6.0
 *
 * Revision 1.34  2005/09/28 15:50:26  ksadasivuni
 * - Merging FreeBSD 6.0 AMD64 Release with CVS Head
 * - Now context pointer given to user space applications is physical pointer.
 *   So there is no need to do cavium_vtophys() of context pointer.
 *
 * Revision 1.33  2005/09/21 06:54:49  lpathy
 * Merging windows server 2003 release with CVS head
 *
 * Revision 1.32  2005/09/14 13:23:39  ksadasivuni
 * - A small fix for handling multiple card initialization.
 *
 * Revision 1.31  2005/09/09 08:55:02  sgadam
 * - Warning Reomoved
 *
 * Revision 1.30  2005/09/06 14:38:57  ksadasivuni
 * - Some cleanup error fixing and spin_lock_destroy functionality added to osi.
 *   spin_lock_destroy was necessary because of FreeBSD 6.0.
 *
 * Revision 1.29  2005/09/06 07:08:22  ksadasivuni
 * - Merging FreeBSD 4.11 Release with CVS Head
 *
 * Revision 1.28  2005/06/29 19:41:26  rkumar
 * 8-byte alignment problem fixed with N1_SANITY define.
 *
 * Revision 1.27  2005/06/13 06:35:42  rkumar
 * Changed copyright
 *
 * Revision 1.26  2005/05/20 14:34:05  rkumar
 * Merging CVS head from india
 *
 * Revision 1.25  2005/02/01 04:11:07  bimran
 * copyright fix
 *
 * Revision 1.24  2005/01/11 00:22:49  mvarga
 * Fixed problems with compiler optimizations.
 *
 * Revision 1.23  2004/08/03 20:44:11  tahuja
 * support for Mips Linux & HT.
 *
 * Revision 1.22  2004/08/02 18:57:31  tsingh
 * fixed bug for loading driver on CN1120
 *
 * Revision 1.21  2004/06/28 20:37:42  tahuja
 * Fixed compiler warnings on NetBSD. changed mdelay in check_completion from 1ms to 2ms.
 *
 * Revision 1.20  2004/06/23 20:34:59  bimran
 * compiler warnings on NetBSD.
 * So much other stuff :-)
 *
 * Revision 1.16  2004/05/05 17:23:54  bimran
 * Moved set_soft_reset() from MC2 to all cases.
 *
 * Revision 1.15  2004/05/05 06:46:31  bimran
 * Fixed general initialization and cleanup routines to dupport multiple devices.
 *
 * Revision 1.14  2004/05/02 19:44:29  bimran
 * Added Copyright notice.
 *
 * Revision 1.13  2004/04/26 23:28:24  bimran
 * Used MAX_CORE_NITROX instead to hard coded values for ctp_base and scaratchpad allocations.
 *
 * Revision 1.12  2004/04/24 04:02:13  bimran
 * Fixed NPLUS related bugs.
 * Added some more debug prints.
 *
 * Revision 1.11  2004/04/23 21:48:22  bimran
 * Fixed SMP compile issue.
 *
 * Revision 1.10  2004/04/22 17:17:08  bimran
 * Modified microcode load verfication functionality to be used only on Nitrox-Lite parts due to some boards debug pins mapping issues.
 *
 * Revision 1.9  2004/04/21 21:33:13  bimran
 * added soem more debug dumps.
 *
 * Revision 1.8  2004/04/21 21:20:08  bimran
 * Added Cavium default debug level
 * Added some prints.
 * Temprarily disabled microcode load verification.
 *
 * Revision 1.7  2004/04/21 19:18:58  bimran
 * NPLUS support.
 *
 * Revision 1.6  2004/04/20 17:42:36  bimran
 * changed get_microcode() to reference microcode from cavium_device structure instead of global mirocode structure.
 *
 * Revision 1.5  2004/04/20 02:25:57  bimran
 * Fixed cavium_init() to use context_max passed in cavium_config structure.
 *
 * Revision 1.4  2004/04/19 18:38:45  bimran
 * Removed admin microcode support.
 *
 * Revision 1.3  2004/04/19 17:26:33  bimran
 * Fixed boot_setup_ucode() which should have always had 8 as dlen for 2.0 microcode.
 *
 * Revision 1.2  2004/04/16 03:20:38  bimran
 * Added doorbell coalescing support.
 * Microcode load verification support.
 *
 * Revision 1.1  2004/04/15 22:40:49  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

