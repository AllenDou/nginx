/* request_manager.c */
/*
 * Copyright (c) 2003-2006 Cavium Networks (support@cavium.com). All rights
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
 * 3. All manuals,brochures,user guides mentioning features or use of this
 *    software must display the following acknowledgement:
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
#include "cavium_endian.h"
#include "cavium_list.h"
#include "cavium.h"
#include "request_manager.h"
#include "command_que.h"
#include "context_memory.h"
#include "init_cfg.h"
#include "buffer_pool.h"
#include "hw_lib.h"
#include "error_handler.h"

extern int dev_count;
extern short nplus, ssl, ipsec, max_q;
extern cavium_device cavium_dev[];
extern struct v2pmap*** map_table;
int cavium_speed_timeout = 0;
extern struct workqueue_struct *work_queue[];
extern struct delayed_work work[];
extern int reset_time;
extern int n3_vf_driver;
int test_queue = 0;

Uint64 get_next_addr(cavium_device *pkp_dev, int q_no);

#ifdef COUNTER_ENABLE
 Uint64 hmac_count =0;
 Uint64 encrypt_count=0;
 Uint64 decrypt_count=0;
 Uint64 encrypt_record_count=0;
 Uint64 decrypt_record_count=0;
 Uint64 ipsec_inbound_count=0;
 Uint64 ipsec_outbound_count=0;
 Uint64 bytes_in_enc =0;
 Uint64 bytes_out_enc =0;
 Uint64 bytes_in_dec =0;
 Uint64 bytes_out_dec =0;
 Uint64 bytes_in_rec_enc =0;
 Uint64 bytes_out_rec_enc =0;
 Uint64 bytes_in_rec_dec =0;
 Uint64 bytes_out_rec_dec =0;
 Uint64 bytes_in_hmac =0;
 Uint64 bytes_out_hmac =0;
 Uint64 bytes_in_ipsec_ib =0;
 Uint64 bytes_out_ipsec_ib =0;
 Uint64 bytes_in_ipsec_ob =0;
 Uint64 bytes_out_ipsec_ob =0;
 Uint64 enc_pkt_err =0;
 Uint64 dec_pkt_err =0;
 Uint64 enc_rec_pkt_err =0;
 Uint64 dec_rec_pkt_err =0;
 Uint64 in_ipsec_pkt_err =0;
 Uint64 out_ipsec_pkt_err =0;
 Uint64 hmac_pkt_err =0;
#endif

extern Uint64 cavium_command_timeout;

void
cavium_dump_op_bytes(n1_operation_buffer *n1_op)
{
   cavium_print("----- do_operation Opcode : (Major: %x Minor: %x) -------\n",
                (n1_op->opcode & 0xff), ((n1_op->opcode & 0xff00) >> 8));
   cavium_print("Size: 0x%x Param: 0x%x dlen: 0x%x, rlen: 0x%x\n",
                n1_op->size, n1_op->param, n1_op->dlen, n1_op->rlen);
   cavium_print("insize[0]: 0x%x inoff[0]: 0x%x\n", n1_op->insize[0],
                n1_op->inoffset[0]);
    cavium_print("outsize[0]: 0x%x outoff[0]: 0x%x\n", n1_op->outsize[0],
               n1_op->outoffset[0]);
   cavium_print("incnt: 0x%x outcnt: 0x%x\n", n1_op->incnt, n1_op->outcnt);
   cavium_print("req_type: 0x%x req_queue: 0x%x resp_ord: 0x%x\n",
                n1_op->req_type, n1_op->req_queue, n1_op->res_order);
   cavium_print("-------------------------------\n\n");
}




static inline void
check_for_pcie_error(cavium_device *pdev)
{
   Uint32  dwval, corr_err, uncorr_err;
   Uint32  corr_mask;
   static Uint32  lnk_ctl_sts, prev_lnk_ctl_sts = 0;
   static Uint32  power_ctl, prev_power_ctl = 0;

   read_PCI_register(pdev, 0x44, &power_ctl);
   read_PCI_register(pdev, 0x80, &lnk_ctl_sts);

   if (power_ctl != prev_power_ctl) {
     cavium_error("Power Control: 0x%08x\n", power_ctl);
   }

   prev_power_ctl = power_ctl;

   if (lnk_ctl_sts != prev_lnk_ctl_sts) {
     cavium_error("Link Control Status: 0x%08x\n", lnk_ctl_sts);
   }

   prev_lnk_ctl_sts = lnk_ctl_sts;

   read_PCI_register(pdev, 0x78, &dwval);
   if(dwval & 0x000f0000) {
      cavium_error("PCI-E error detected: 0x%08x\n", dwval & 0x000f0000);
      if(dwval & 0x00010000) {
         read_PCI_register(pdev, 0x110, &corr_err);
         if(corr_err) {
            cavium_error("Correctable error: 0x%08x\n", corr_err);
            write_PCI_register(pdev, 0x110, corr_err);
         } else {
            read_PCI_register(pdev, 0x114, &corr_mask);
            cavium_error("Config[0x78] is 0x%08x but CEStatus is 0x%08x, CEMask is 0x%08x\n", dwval, corr_err, corr_mask);
         }
      }
      if(dwval & 0x0004000) {
         read_PCI_register(pdev, 0x104, &uncorr_err);
         if(uncorr_err) {
            cavium_error("Uncorrectable error: 0x%08x\n", uncorr_err);
            write_PCI_register(pdev, 0x104, uncorr_err);
         }
      }
      write_PCI_register(pdev, 0x78,(dwval & ~(0x000f0000)));
   }
}


int send_command(cavium_device *n1_dev, Request *request, int queue, int ucode_idx, Uint64 *ccptr)
{
   int ret=0;
   Uint8 * command;
   struct MICROCODE *microcode = NULL;
   short plus_check = (nplus || ssl>0 || ipsec > 0);

    MPRINTFLOW();
   if (plus_check) {
       Uint64  core_grp64;;
       microcode = &(n1_dev->microcode[ucode_idx]);
       core_grp64 = (Uint64)microcode->core_grp;
      cavium_dbgprint("send_command: core grp for ucode[%d]: %d\n",
                       ucode_idx, microcode->core_grp);
      /* Set the core group here. The cptr would be in big-endian mode.*/
#if __CAVIUM_BYTE_ORDER == __CAVIUM_BIG_ENDIAN
      /* Bits 62-61 of cptr store the queue index. */
      request->cptr |= (core_grp64 << 61);
#else
      /* Bits 6-5 of the last byte (MSB) of cptr stores the queue index. */
      request->cptr |= (core_grp64 << 5);
#endif
  }
   {
     if (cavium_debug_level > 1)
         cavium_dump("Request:", (Uint8 *)request,32);
     
   /* Send command to the chip */
      lock_command_queue(n1_dev, queue);
      command = (Uint8 *)(n1_dev->command_queue_front[queue]);
      cavium_memcpy(command, (Uint8 *)request, COMMAND_BLOCK_SIZE);
      inc_front_command_queue(n1_dev, queue);
#ifdef CAVIUM_NO_NC_DMA
      cavium_flush_cache(n1_dev, COMMAND_BLOCK_SIZE, command, NULL, 0);
#endif

      cavium_wmb();


   /* doorbell coalescing */
      n1_dev->door_bell_count[queue]++;
      if((n1_dev->door_bell_count[queue] >= n1_dev->door_bell_threshold[queue])
      )
      {
         cavium_dbgprint("send command: hitting doorbell: %d\n", n1_dev->door_bell_count[queue]);
         ring_door_bell(n1_dev, queue, n1_dev->door_bell_count[queue]);
         n1_dev->door_bell_count[queue]=0;
      }

      unlock_command_queue(n1_dev, queue);
   }
   return ret;
}

void do_post_process(cavium_device *n1_dev, n1_user_info_buffer *user_info)
{
     Uint64 *p;
     int i;
#ifdef COUNTER_ENABLE
    Uint8 major_op;
    Uint8 minor_op;
#endif
     cavium_invalidate_cache(n1_dev, user_info->rlen,
                          user_info->rptr, 
                          user_info->rptr_baddr, 
                          CAVIUM_PCI_DMA_BIRECTIONAL);
      
      cavium_unmap_kernel_buffer(n1_dev, 
                          user_info->dptr_baddr, 
                          user_info->dlen, 
                          CAVIUM_PCI_DMA_BIDIRECTIONAL);
      cavium_unmap_kernel_buffer(n1_dev,
                          user_info->rptr_baddr,
                          user_info->rlen+COMPLETION_CODE_SIZE,
                          CAVIUM_PCI_DMA_BIDIRECTIONAL);
      if (user_info->out_size)
      {
       if (user_info->gflag)
       {
         int glist_indx=-1;
         int xx;
         Uint32 gbuf_used=0, gbuf_remain=0;
         if (cavium_debug_level > 2)
         {
            cavium_print("Gather List Response Pkt:\n");
            for (xx = 0; xx < user_info->glist_cnt; xx++)
               cavium_dump ("Gather_Buffer:", (Uint8 *)user_info->glist_ptr[xx], user_info->glist_ptrsize[xx]);
         }
         for (i = 0; i < user_info->outcnt; i++)
         {
            if (gbuf_remain==0) {
               glist_indx++;
               gbuf_used=0;
               gbuf_remain=user_info->glist_ptrsize[glist_indx];
            }
            if (user_info->outunit[i] == UNIT_64_BIT)
            {
               p = (Uint64 *)((unsigned long)(user_info->glist_ptr[glist_indx])+gbuf_used);
               *p = htobe64(*p);
            }
            if (gbuf_remain >= user_info->outsize[i])
            {
               if(cavium_copy_out(user_info->outptr[i],
                     (Uint8*)((unsigned long)user_info->glist_ptr[glist_indx]+gbuf_used),
                     user_info->outsize[i]))
               {
                  cavium_error("Failed to copy out %d bytes to user buffer 0x%lx\n",
                        user_info->outsize[i], (ptrlong)user_info->outptr[i]);
               }
               gbuf_used += user_info->outsize[i];
               gbuf_remain -= user_info->outsize[i];
            }
            else
            {
               Uint32 outptr_offset=0, gout_size = user_info->outsize[i];
               Uint32 get_size;
               while (gout_size)
               {
                  if (gbuf_remain==0) {
                     glist_indx++;
                     gbuf_used=0;
                     gbuf_remain=user_info->glist_ptrsize[glist_indx];
                  }
                  get_size = (gbuf_remain >= gout_size)?gout_size:gbuf_remain;
                  if(cavium_copy_out((Uint8*)
                            ((unsigned long)user_info->outptr[i]+outptr_offset),
                            (Uint8*)((unsigned long)user_info->glist_ptr[glist_indx]+gbuf_used),
                    get_size))
                  {
                     cavium_error("Failed to copy out %d bytes to user buffer 0x%lx\n",
                           user_info->outsize[i], (ptrlong)user_info->outptr[i]);
                  }
                  gbuf_remain -= get_size;
                  gbuf_used += get_size;
                  gout_size -= get_size;
                  outptr_offset += get_size;
               }
            }
         }
      }
      else
         {
         int total_offset;
         if (cavium_debug_level > 2)
            cavium_dump("Response Pkt:", (Uint8 *)user_info->out_buffer, user_info->out_size);
         total_offset = 0;
         for (i = 0; i < user_info->outcnt; i++)
         {
            if (user_info->outunit[i] == UNIT_64_BIT)
            {
               p = (Uint64 *)&user_info->out_buffer[total_offset];
               *p = htobe64(*p);
            }
            if(cavium_copy_out(user_info->outptr[i],
                  &user_info->out_buffer[total_offset],
                  user_info->outsize[i]))
            {
               cavium_error("Failed to copy out %d bytes to user buffer 0x%lx\n",
                     user_info->outsize[i], (ptrlong)user_info->outptr[i]);
            }
            total_offset += user_info->outoffset[i];
         }
       }
      }
#ifdef COUNTER_ENABLE
     major_op=(Uint8)(user_info->opcode&0xff);
     minor_op=(Uint8)((user_info->opcode>>8)&0xff);
     switch (major_op)
     {
         case MAJOR_OP_ENCRYPT_DECRYPT:
                    if(minor_op & 0x01){
                      decrypt_count++;
                      bytes_in_dec = bytes_in_dec + (Uint64) user_info->dlen;
                      bytes_out_dec = bytes_out_dec + (Uint64)user_info->rlen-8;
                      if(user_info->status)
                       dec_pkt_err++; 
                    }
                    else{
                       encrypt_count++;
                       bytes_in_enc = bytes_in_enc + (Uint64) user_info->dlen;
                       bytes_out_enc = bytes_out_enc + (Uint64) user_info->rlen-8;
                       if(user_info->status)
                        enc_pkt_err++;
                    }
                      break;
         case MAJOR_OP_ENCRYPT_DECRYPT_RECORD:
                    if(minor_op & 0x40) {
                    encrypt_record_count++;
                    bytes_in_rec_enc = bytes_in_rec_enc + (Uint64) user_info->dlen;
                    bytes_out_rec_enc = bytes_out_rec_enc + (Uint64) user_info->rlen-8;
                    if(user_info->status)
                       enc_rec_pkt_err++;
                   }
                   else {
                    decrypt_record_count++;
                    bytes_in_rec_dec = bytes_in_rec_dec + (Uint64) user_info->dlen;
                    bytes_out_rec_dec = bytes_out_rec_dec + (Uint64) user_info->rlen-8;
                    if(user_info->status)
                       dec_rec_pkt_err++; 
                  }
                   break;
         case MAJOR_OP_HMAC:
                   hmac_count++;
                   bytes_in_hmac = bytes_in_hmac + (Uint64) user_info->dlen;
                   bytes_out_hmac = bytes_out_hmac + (Uint64) user_info->rlen-8;
                   if(user_info->status)
                     hmac_pkt_err++;
                   break;  
         case OP_IPSEC_PACKET_INBOUND:
                 ipsec_inbound_count++;
                 bytes_in_ipsec_ib = bytes_in_ipsec_ib + (Uint64) user_info->dlen;
                 bytes_out_ipsec_ib = bytes_out_ipsec_ib  + (Uint64) user_info->rlen;
                 if(user_info->status)
                   in_ipsec_pkt_err++; 
                 break;
         case OP_IPSEC_PACKET_OUTBOUND:
                 ipsec_outbound_count++;
                 bytes_in_ipsec_ob = bytes_in_ipsec_ob + (Uint64) user_info->dlen;
                 bytes_out_ipsec_ob = bytes_out_ipsec_ob + (Uint64) user_info->rlen;
                 if(user_info->status)
                 out_ipsec_pkt_err++; 
                 break;
         default: cavium_dbgprint("No data counter related opcode");
       }
#endif
     for (i = 0; i < user_info->slist_cnt; i++)
         put_buffer_in_pool ( user_info->slist_ptr[i],user_info->slist_ptrsize[i]);
      for (i = 0; i < user_info->glist_cnt; i++)
         put_buffer_in_pool (user_info->glist_ptr[i],user_info->glist_ptrsize[i]);
    if (user_info->in_buffer)
      put_buffer_in_pool((Uint8 *)user_info->in_buffer,user_info->dlen);
   if (user_info->out_buffer)
       put_buffer_in_pool((Uint8 *)user_info->out_buffer,user_info->rlen);
   if (user_info)
       put_buffer_in_pool((Uint8 *)user_info,sizeof(n1_user_info_buffer));
}

int check_nb_command_id(cavium_device *n1_dev, void *private_data, Uint32 request_id)
 {
    struct cavium_list_head *tmp, *tmp1;
    Uint32 ret=ERR_INVALID_REQ_ID;
    Uint8 status=0;
    CMD_DATA *cmd_data=NULL;
    cavium_device *dev=NULL;
    int queue=0;
    
    n1_user_info_buffer *user_info=NULL;
    tracking_list *track_list=(tracking_list *)private_data;
    if(!track_list){
        return ret;
    }
    if(!track_list->pending)
        return ret;
    cavium_spin_lock_softirqsave(&track_list->nbl_lock);
    cavium_list_for_each_safe(tmp,tmp1,&track_list->nbl)
    {
         user_info=list_entry(tmp, n1_user_info_buffer, list);
         if(user_info == NULL)
         {
             printk(KERN_CRIT "RequestId %d not found\n",request_id);
             cavium_spin_unlock_softirqrestore(&track_list->nbl_lock);
             return ret;
         }
         if(user_info->request_id == request_id)
         {
            status=(Uint8)*((Uint8 *)user_info->completion_addr);
            if((status == 0xff) && ((user_info->time_in+cavium_command_timeout) >(Uint64) cavium_jiffies)){
                cavium_spin_unlock_softirqrestore(&track_list->nbl_lock);
                return ERR_REQ_PENDING;
             }else if(status== 0xff){
                Uint32 dwval=0;
                Uint32 dwval1=0;
                Uint32 rval=0;
                Uint32 wval=0;
                dev=user_info->n1_dev;
               if(dev->device_id == NPX_DEVICE){    
                read_PKP_register(dev, (dev->CSRBASE_A + 0x208+ (user_info->queue * 0x10)), &dwval);
                read_PKP_register(dev, (dev->CSRBASE_B + REQ0_BASE_LOW + (user_info->queue *0x20)), &dwval1);
                rval= (dwval-dwval1)/COMMAND_BLOCK_SIZE;
               }else if(dev->device_id == N3_DEVICE){
                   Uint64 read=0ULL;
                   Uint8 *rptr=NULL;
                   read = get_next_addr(dev,user_info->queue);
                   rptr = bus_to_virt(read);
                   dwval=(Uint32)(rptr-((Uint8 *)(ptrlong)dev->command_queue_base[user_info->queue])); 
                   rval=dwval/COMMAND_BLOCK_SIZE; 
               }
              wval = dev->command_queue_front[user_info->queue] - dev->command_queue_base[user_info->queue];
              wval = wval / COMMAND_BLOCK_SIZE;
              dwval = user_info->index;
                if(((wval > rval) && (rval <= dwval))||!((wval<dwval) && (dwval <= rval)))
                 {
                  user_info->time_in=cavium_jiffies;
                  cavium_spin_unlock_softirqrestore(&track_list->nbl_lock);
                  return ERR_REQ_PENDING;
                }
             }
             cavium_list_del(&user_info->list);
             track_list->pending--;
             break;
         }else
            user_info=NULL;
    }
     cavium_spin_unlock_softirqrestore(&track_list->nbl_lock);
    if(user_info==NULL){
       printk(KERN_CRIT "RequestId %d not found\n",request_id);
        return ERR_INVALID_REQ_ID;
    }
    if(status == 0xff)
    {
         ret=ERR_REQ_TIMEOUT;
         cavium_error(" REQUEST TIMED OUT \n");
    }
    else
      ret=(Uint32)status;
    if(user_info->status){
         dev=user_info->n1_dev;
         cmd_data = user_info->cmd_data;
         if(cmd_data){
           queue=user_info->queue;
           cavium_spin_lock_softirqsave(&(dev->pending_queue[queue].pending_lock));   
           cmd_data->done=1;
           cavium_spin_unlock_softirqrestore(&(n1_dev->pending_queue[queue].pending_lock));   
        }
     }
    user_info->status=ret;
    
    do_post_process(n1_dev,user_info);
    return (int)ret;
   
 }

/*check for the status of pending requests*/
Uint32
check_all_nb_command(cavium_device *pdev,void *data, Csp1StatusOperationBuffer *csp1_status_operation)
{
   Uint32 cnt = 0;
   Uint32 res_cnt = 0;
   Uint32 ret=0;
   /*number of request ids to be checked for*/
   Uint32 req_cnt = csp1_status_operation->cnt;

   Csp1RequestStatusBuffer *req_stat_buf = (void *)(ptrlong) (csp1_status_operation->req_stat_buf);

   Csp1RequestStatusBuffer *resp_stat_buf = NULL;

   MPRINTFLOW();
   resp_stat_buf =
        (Csp1RequestStatusBuffer *) get_buffer_from_pool(pdev,
                                      req_cnt * sizeof (Csp1RequestStatusBuffer));
   if (resp_stat_buf == NULL)
      return ERR_MEMORY_ALLOC_FAILURE;

   while(cnt < req_cnt)
   {
       ret = check_nb_command_id(pdev, data, req_stat_buf[cnt].request_id);
  /*res_stat_buf is updated only for completed and pending(ERR_REQ_PENDING)
   *requests*/ 
       //if(ret != ERR_INVALID_REQ_ID)
       {
          resp_stat_buf[res_cnt].request_id =req_stat_buf[cnt].request_id;
          resp_stat_buf[res_cnt].status = ret;
          res_cnt++;
       }
       cnt++;
   }
   
   if(cavium_copy_out((void *)(ptrlong) (csp1_status_operation->req_stat_buf), 
                  resp_stat_buf,
                  res_cnt * sizeof(Csp1RequestStatusBuffer)))
   {
      return EFAULT;
   }
   csp1_status_operation->res_count = res_cnt;             

   put_buffer_in_pool((Uint32 *) resp_stat_buf,req_cnt * sizeof(Csp1RequestStatusBuffer));

   return 0;
}
int free_pending_queue(int cpu ,int free_count ,cavium_device * dev)
{   
    int i = 0;
    Uint8 major_op,minor_op;
    void (*cb)(int,void *) = NULL;  
    CMD_DATA *cmd_data = NULL;
    cavium_device *pdev =NULL;
    void *cb_arg = NULL;
    Uint8 status;
    Uint64 cond_code=0;
    n1_kernel_info_buffer *kernel_info = NULL;
    n1_user_info_buffer *user_info = NULL;
    pending_queue_t *pqueue;
    
    pdev = dev;
    pqueue=&(pdev->pending_queue[cpu]);

    while(i++ < free_count || !free_count) {
       cavium_spin_lock_softirqsave(&(pqueue->pending_lock)); 
       cmd_data=(CMD_DATA *)&(pqueue->cmd_queue[pqueue->queue_front]);
       if(cmd_data->free ==1){
         cavium_spin_unlock_softirqrestore(&(pqueue->pending_lock));   
         return 1;
       }  
       if(cmd_data->is_user){
        if(cmd_data->done)
        {
           cmd_data->cb=NULL;
           cmd_data->is_user=0;
           cmd_data->free=1;
           cmd_data->cb_arg=NULL;
           pqueue->queue_front++;
           if(pqueue->queue_front == pqueue->queue_size) 
              pqueue->queue_front = 0; 
           cavium_spin_unlock_softirqrestore(&(pqueue->pending_lock));   
           continue;
        }
        user_info = (n1_user_info_buffer *)cmd_data->post_arg;
        if(!user_info){
          cavium_spin_unlock_softirqrestore(&(pqueue->pending_lock));   
          return -1;
        }
        status = ((Uint8 *)user_info->completion_addr)[0];
        if(status == 0xff){
         if((cavium_jiffies - user_info->time_in) < CAVIUM_DEFAULT_TIMEOUT){
           cavium_spin_unlock_softirqrestore(&(pqueue->pending_lock));   
           break;
         }else
         {
             Uint32 dwval=0;
             Uint32 dwval1=0;
             Uint32 rval=0;
             Uint32 wval=0;
             cavium_device *dev=NULL;
             dev=user_info->n1_dev;
             if(dev->device_id == NPX_DEVICE){    
                read_PKP_register(dev, (dev->CSRBASE_A + 0x208+ (user_info->queue * 0x10)), &dwval);
                read_PKP_register(dev, (dev->CSRBASE_B + REQ0_BASE_LOW + (user_info->queue *0x20)), &dwval1);
                rval= (dwval-dwval1)/COMMAND_BLOCK_SIZE;
               }else if(dev->device_id == N3_DEVICE){
                   Uint64 read=0ULL;
                   Uint8 *rptr=NULL;
                   read = get_next_addr(dev,user_info->queue);
                   rptr = bus_to_virt(read);
                   dwval=(Uint32)(rptr-((Uint8 *)(ptrlong)dev->command_queue_base[user_info->queue])); 
                   rval=dwval/COMMAND_BLOCK_SIZE; 
               }
              wval = dev->command_queue_front[user_info->queue] - dev->command_queue_base[user_info->queue];
              wval = wval / COMMAND_BLOCK_SIZE;
              dwval = user_info->index;
              if(((wval > rval) && (rval <= dwval))||!((wval<dwval) && (dwval <= rval)))
              {
                  user_info->time_in=cavium_jiffies;
                  cavium_spin_unlock_softirqrestore(&(pqueue->pending_lock));   
                  break;
              }
            }
        }
        user_info->status=0;
        if(user_info->req_type == CAVIUM_BLOCKING)
           cavium_wakeup(&user_info->channel);
        cmd_data->cb=NULL;
        cmd_data->cb_arg=NULL;
        pqueue->queue_front++;
        if(pqueue->queue_front == pqueue->queue_size) {
          pqueue->queue_front = 0; 
        }
        cmd_data->free=1;
        cavium_spin_unlock_softirqrestore(&(pqueue->pending_lock));   
    }else{ 
        kernel_info=NULL;
        kernel_info=(n1_kernel_info_buffer *)cmd_data->post_arg;
        cb=cmd_data->cb;
        cb_arg=cmd_data->cb_arg;
        if((kernel_info == NULL)){
          cavium_spin_unlock_softirqrestore(&(pqueue->pending_lock));   
          return -1;
        }
        status=((Uint8 *)kernel_info->completion_addr)[0];
        if(status == 0xff){
         /* Check for TIMEOUT */
         if((cavium_jiffies - kernel_info->time_in) >=CAVIUM_DEFAULT_TIMEOUT){
             Uint32 dwval=0;
             Uint32 dwval1=0;
             Uint32 rval=0;
             Uint32 wval=0;
             cavium_device *dev=NULL;
             dev=pdev;
             if(dev->device_id == NPX_DEVICE){    
                read_PKP_register(dev, (dev->CSRBASE_A + 0x208+ (cpu * 0x10)), &dwval);
                read_PKP_register(dev, (dev->CSRBASE_B + REQ0_BASE_LOW + (cpu *0x20)), &dwval1);
                rval= (dwval-dwval1)/COMMAND_BLOCK_SIZE;
               }else if(dev->device_id == N3_DEVICE){
                   Uint64 read=0ULL;
                   Uint8 *rptr=NULL;
                   read = get_next_addr(dev,cpu);
                   rptr = bus_to_virt(read);
                   dwval=(Uint32)(rptr-((Uint8 *)(ptrlong)dev->command_queue_base[cpu])); 
                   rval=dwval/COMMAND_BLOCK_SIZE; 
               }
              wval = dev->command_queue_front[cpu] - dev->command_queue_base[cpu];
              wval = wval / COMMAND_BLOCK_SIZE;
              dwval = pqueue->queue_front;
              if(((wval > rval) && (rval <= dwval))||!((wval<dwval) && (dwval <= rval)))
              {
                  kernel_info->time_in=cavium_jiffies;
                  cavium_spin_unlock_softirqrestore(&(pqueue->pending_lock));   
                  break;
              }
              cond_code=ERR_REQ_TIMEOUT;
         }
         else{
          cavium_spin_unlock_softirqrestore(&(pqueue->pending_lock));   
           break;
         }
        }
        cmd_data->cb=NULL;
        cmd_data->cb_arg=NULL;
        pqueue->queue_front++;
        if(pqueue->queue_front == pqueue->queue_size) {
          pqueue->queue_front = 0; 
        }
        cmd_data->free=1;
        if(!cond_code)
         cond_code=check_completion_code((Uint64 *)kernel_info->completion_addr);
        cavium_spin_unlock_softirqrestore(&(pqueue->pending_lock));   
    
     #ifdef COUNTER_ENABLE
        major_op=(Uint8)(kernel_info->opcode & 0xff);
        minor_op=(Uint8)((kernel_info->opcode >> 8) & 0xff);
        switch (major_op)
        {
          case MAJOR_OP_ENCRYPT_DECRYPT:
            if(minor_op & 0x01) {
              decrypt_count++;
              bytes_in_dec = bytes_in_dec + (Uint64) kernel_info->dlen;
              bytes_out_dec = bytes_out_dec + (Uint64) kernel_info->rlen;
              if(cond_code)
                dec_pkt_err++;
            }
            else {
              encrypt_count++;
              bytes_in_enc = bytes_in_enc + (Uint64) kernel_info->dlen;
              bytes_out_enc = bytes_out_enc + (Uint64) kernel_info->rlen;
              if(cond_code)
               enc_pkt_err++;
            }
            break;
          case MAJOR_OP_ENCRYPT_DECRYPT_RECORD:
            if(minor_op & 0x40) {
              encrypt_record_count++;
              bytes_in_rec_enc = bytes_in_rec_enc + (Uint64) kernel_info->dlen;
              bytes_out_rec_enc = bytes_out_rec_enc + (Uint64) kernel_info->rlen;
              if(cond_code)
               enc_rec_pkt_err++;
            }
            else {
              decrypt_record_count++;
              bytes_in_rec_dec = bytes_in_rec_dec + (Uint64) kernel_info->dlen;
              bytes_out_rec_dec = bytes_out_rec_dec + (Uint64) kernel_info->rlen;
              if(cond_code)
                dec_rec_pkt_err++;
            }
            break;
          case MAJOR_OP_HMAC:
            hmac_count++;
            bytes_in_hmac = bytes_in_hmac + (Uint64) kernel_info->dlen;
            bytes_out_hmac = bytes_out_hmac + (Uint64) kernel_info->rlen;
            if(cond_code)
              hmac_pkt_err++;
            break;
          case (int) OP_IPSEC_PACKET_INBOUND:
            ipsec_inbound_count++;
            bytes_in_ipsec_ib = bytes_in_ipsec_ib + (Uint64) kernel_info->dlen;
            bytes_out_ipsec_ib = bytes_out_ipsec_ib  + (Uint64) kernel_info->rlen;
            if(cond_code)
              in_ipsec_pkt_err++; 
            break;
          case (int) OP_IPSEC_PACKET_OUTBOUND:
            ipsec_outbound_count++;
            bytes_in_ipsec_ob = bytes_in_ipsec_ob + (Uint64) kernel_info->dlen;
            bytes_out_ipsec_ob = bytes_out_ipsec_ob + (Uint64) kernel_info->rlen;
            if(cond_code)
              out_ipsec_pkt_err++; 
            break;
          default: cavium_dbgprint("No data counter related opcode\n");
      }
     #endif

      if(kernel_info->dma_mode == CAVIUM_SCATTER_GATHER)
      {
        pkp_invalidate_output_buffers(pdev, kernel_info);
        cavium_unmap_kernel_buffer(pdev,kernel_info->sg_dma_baddr, 
                                    kernel_info->sg_dma_size,
                                    CAVIUM_PCI_DMA_TODEVICE);
        pkp_unmap_user_buffers(pdev, kernel_info);
        put_completion_dma(pdev, &kernel_info->completion_dma);
        put_buffer_in_pool(kernel_info, sizeof(n1_kernel_info_buffer)); 
        if(cb)
        cb(cond_code, cb_arg);
      }else
      {
          cavium_invalidate_cache(pdev,kernel_info->rlen+8, 
                                  kernel_info->rptr,
                                  kernel_info->rptr_baddr,
                                  CAVIUM_PCI_DMA_BIDIRECTIONAL);
         
         if(kernel_info->dptr_baddr)
           cavium_unmap_kernel_buffer(pdev, kernel_info->dptr_baddr,
                                      kernel_info->dlen, 
                                      CAVIUM_PCI_DMA_BIDIRECTIONAL);
         if(kernel_info->rptr_baddr)
           cavium_unmap_kernel_buffer(pdev, kernel_info->rptr_baddr, 
                                      kernel_info->rlen+COMPLETION_CODE_SIZE, 
                                      CAVIUM_PCI_DMA_BIDIRECTIONAL);
         put_buffer_in_pool(kernel_info, sizeof(n1_kernel_info_buffer)); 
        if(cb)
         cb(cond_code,cb_arg);
      }
    }
   }
   return 0;
}
int 
do_request(cavium_device * n1_dev, n1_request_buffer *req, Uint32 *req_id)
{
   int r,ret = 0;
   volatile Uint64 *completion_address;
   Cmd *strcmd;
   Request request;
   CMD_DATA *cmd_data;
   int offset=0;
   n1_kernel_info_buffer *kernel_info = NULL;
   MPRINTFLOW();
   kernel_info = (n1_kernel_info_buffer *)get_buffer_from_pool(n1_dev,
                  sizeof(n1_kernel_info_buffer));
    if(!kernel_info)
       return 1;
    memset(kernel_info, 0x0, sizeof(n1_kernel_info_buffer));
   
   if(req->ctx_ptr){      
      offset=req->ctx_ptr&0x7FF;
      req->ctx_ptr=req->ctx_ptr&~(0x7FF);
      req->ctx_ptr = ((struct ctx_addr *)(CAST_FRM_X_PTR(req->ctx_ptr)))->phy_addr;
      req->ctx_ptr+=offset;
   }
    
   kernel_info->n1_dev=n1_dev;
   strcmd=(Cmd *)&(request.cmd);
   kernel_info->opcode=req->opcode;
   switch(req->dma_mode)
   {
      case CAVIUM_DIRECT:
      {
           kernel_info->ctx_ptr=req->ctx_ptr;
           kernel_info->req_type=req->req_type;
           kernel_info->n1_dev=n1_dev;
           kernel_info->dma_mode=req->dma_mode;
          
         /* Setup direct operation -- fill in {d,r,c}ptr */
         if(pkp_setup_direct_operation(n1_dev,req, kernel_info))
         {
            cavium_dbgprint("do_request: map kernel buffer failed\n");
            ret = ERR_DMA_MAP_FAILURE;
            goto cleanup_direct;
         }


         /* write completion address of all 1's */
         completion_address = kernel_info->completion_addr;
         strcmd->opcode = htobe16(req->opcode);
         strcmd->size = htobe16(req->size);
         strcmd->param = htobe16(req->param);
         strcmd->dlen = htobe16(kernel_info->dlen);

         cavium_dbgprint("Sending request with Opcode: 0x%x\n",
                   (Uint32)strcmd->opcode);
         /* Setup dptr */
         if (kernel_info->dptr)
         {
            request.dptr = htobe64(kernel_info->dptr_baddr);
         }
         else
         {
            request.dptr = 0;
         }

         /* Setup rptr */
         request.rptr = htobe64(kernel_info->rptr_baddr);
         /* Setup cptr */
         if (kernel_info->ctx_ptr)
         {
               request.cptr = htobe64(kernel_info->ctx_ptr);
         }
         else
         {
            request.cptr = 0;
         }

         if(cavium_debug_level > 2)
#ifdef MC2
            cavium_dump("dptr", kernel_info->dptr, kernel_info->dlen);
#else
            cavium_dump("DPTR", kernel_info->dptr, kernel_info->dlen*8);
#endif
         break;
      }
      case CAVIUM_SCATTER_GATHER:
      {
         /*
          * Get a scatter/gather operation struct from free pool
          */
         /*
          * to scatter/gather module
          */
         /* Setup scatter/gather list */
         if (pkp_setup_sg_operation(n1_dev, req,
                     kernel_info))
         {
            ret = ERR_SCATTER_GATHER_SETUP_FAILURE;
            goto cleanup_sg;
         }

         cavium_dbgprint("do_req: completion address = %p\n", (void *)kernel_info->completion_dma.vaddr);

         /* write completion address of all 1's  */
         completion_address = (volatile Uint64 *)(kernel_info->completion_dma.vaddr);
         kernel_info->completion_addr = completion_address;

         /*
          * Build the 8 byte command(opcode,size,param,dlen)
          * and put it in the request structure
          */
         cavium_dbgprint("do_req: building command\n");
         strcmd->opcode = htobe16((req->opcode|(0x1 << 7)));
         strcmd->size = htobe16(req->size);
         strcmd->param = htobe16(req->param);
         strcmd->dlen =
            htobe16((8 +
           (((kernel_info->gather_list_size + 3)/4
           +(kernel_info->scatter_list_size + 3)/4) * 40)));
#ifndef MC2
         strcmd->dlen = strcmd->dlen>>3;
#endif

         /* Setup dptr */
         cavium_dbgprint("do_req: setting up dptr\n");
         request.dptr = kernel_info->sg_dma_baddr;
         request.dptr = htobe64(request.dptr);

         /* Setup rptr */ /*Uncommenting. This should be the case -kchunduri*/
         cavium_dbgprint("do_req: setting up rptr\n");
         request.rptr
         = htobe64((Uint64)kernel_info->completion_dma.baddr);


         cavium_dbgprint ( "rptr = %llx \n",(long long) request.rptr  ) ;

         /* Setup cptr */
         cavium_dbgprint("do_req: setting up cptr\n");
         if (kernel_info->ctx_ptr)
         {
               request.cptr = htobe64(kernel_info->ctx_ptr);
         }
         else
         {
            request.cptr = 0;
         }

         break;
      }
      default:
         cavium_error("Unknown dma mode\n");
         ret = ERR_INVALID_COMMAND;
         return ret;
   }

   /* Send the command to the chip */
   if(max_q)
   {
      r = n1_dev->curr_q;
      n1_dev->curr_q = (n1_dev->curr_q + 1) % n1_dev->max_queues;      
   }
   else
      r=smp_processor_id()%(n1_dev->max_queues);
find_cmdblock_again:
   kernel_info->time_in = cavium_jiffies;
   cavium_spin_lock_softirqsave(&(n1_dev->pending_queue[r].pending_lock));   
   cmd_data=(CMD_DATA *)(&((n1_dev->pending_queue[r].cmd_queue)[n1_dev->pending_queue[r].queue_rear]));
   if(!cmd_data->free) //pending queue full
   {   
       cavium_dbgprint("Pending queue %d full \n",r);
       cavium_spin_unlock_softirqrestore(&(n1_dev->pending_queue[r].pending_lock)); 
       free_pending_queue(r, 10,n1_dev); 
       goto find_cmdblock_again;
   }

   if(!cmd_data->free) {
      cavium_spin_unlock_softirqrestore(&(n1_dev->pending_queue[r].pending_lock)); 
      ret = -1;
      goto cleanup_direct;
   }

   n1_dev->pending_queue[r].queue_rear++;
   if(n1_dev->pending_queue[r].queue_rear == n1_dev->pending_queue[r].queue_size)
        n1_dev->pending_queue[r].queue_rear=0;
   cmd_data->cb=CAST_FRM_X_PTR(req->callback);
   cmd_data->cb_arg=CAST_FRM_X_PTR(req->cb_arg);
   cmd_data->completion_addr=kernel_info->completion_addr;
   cmd_data->post_arg=(void *)kernel_info;
   cmd_data->free=0;
   cmd_data->is_user=0;
   cavium_spin_unlock_softirqrestore(&(n1_dev->pending_queue[r].pending_lock));   
   //cavium_dbgprint ("do_request: calling send_command()\n");
   send_command(n1_dev, &request, r, req->ucode_idx, (Uint64 *)completion_address);
   ret = 0;

//#if defined(NITROX_PX) && !defined(CN1500) && defined(ENABLE_PCIE_ERROR_REPORTING)

#ifdef ENABLE_PCIE_ERROR_REPORTING
   if((n_dev->device_id ==NPX_DEVICE && n_dev->px_flag!=CN15XX)|| n_dev->device_id == N3_DEVICE)
      check_for_pcie_error(n1_dev);
#endif


   return ret;

cleanup_direct:
   if (kernel_info)
   {
      pkp_unsetup_direct_operation(n1_dev, kernel_info);
      put_buffer_in_pool((Uint8 *)kernel_info, sizeof(n1_kernel_info_buffer));
   }
   return ret;

cleanup_sg:
   if (kernel_info){
      put_completion_dma(n1_dev,&(kernel_info->completion_dma));
      put_buffer_in_pool((Uint8 *)kernel_info, sizeof(n1_kernel_info_buffer));
   }
    return ret;
 
}

void work_queue_handler(struct work_struct *w)
{
    int i,pid;
    pid=smp_processor_id();
    for(i=0;i<dev_count;i++){
      while(pid < cavium_dev[i].max_queues)
      {
         if(reset_time)
           return;
         if(pid >= cavium_dev[i].max_queues)
           break;
         free_pending_queue(pid,0,&cavium_dev[i]); 
         pid = pid + num_online_cpus();
      }
      pid = smp_processor_id();
    }
}

/*
 * n1_operation_buffer = n1_request_buffer + blocking/non-blocking
 *                   operation.
 *
 *
 */

int
do_operation(cavium_device * n1_dev, n1_operation_buffer *n1_op,void *data)
{

   n1_user_info_buffer *user_info = NULL;
   Uint8 *in_buffer = NULL, *out_buffer = NULL;
   Uint64 *p;
   Cmd *cmd;
   Request request;
   CMD_DATA *cmd_data=NULL;
   int queue=0;
   volatile Uint64 *req_compl_addr;
   int mapped = 0;
   Uint32 total_size = 0;
   Uint32 i;
   Uint32 dlen,rlen;
   Uint32 slist_cnt=0,glist_cnt=0;
   int ret=0;
   Uint32 g_flag=0,s_flag=0;
   int offset=0;
   int index;
   MPRINTFLOW();
   dlen = n1_op->dlen;
   rlen = ROUNDUP8(n1_op->rlen + 8);
   user_info = (n1_user_info_buffer *)get_buffer_from_pool(n1_dev,
                  sizeof(n1_user_info_buffer));

   if (user_info == NULL)
   {
      cavium_error(" OOM for user_info buffer\n");
      ret = 1;
      goto do_op_clean;
   }
 
   memset(user_info, 0x0, sizeof(n1_user_info_buffer));
   if(n1_op->req_type != CAVIUM_BLOCKING) 
   {
      tracking_list *track_list=(tracking_list *)data;
      if(!track_list){
          ret=1;
          goto do_op_clean;
      }
      cavium_spin_lock_softirqsave(&track_list->nbl_lock);
      cavium_list_add_tail(&user_info->list, &track_list->nbl);
      user_info->request_id=track_list->next++;
      if(track_list->next == 0xffffffff)
          track_list->next=1;
      track_list->pending++;
      cavium_spin_unlock_softirqrestore(&track_list->nbl_lock);
      n1_op->request_id = user_info->request_id;
   }

   mapped = 0;

/*
 * To use USER_SCATTER option, dma_mode must be set to CAVIUM_SCATTER_GATHER,
 * if 'dlen' and/or 'rlen'> scatter_thold then create multiple buffers of
 * SCATTER_CHUNK size, total_size of all buffers is equal to 'dlen' and/or
 * 'rlen'
 */
   if (dlen)
   {
      if (n1_op->dma_mode==CAVIUM_SCATTER_GATHER && dlen > SCATTER_THOLD)
      {
         Uint8 *buffer = NULL;
         Uint32 buf_size=0, avail_size=0, used_size=0, require_size;
         slist_cnt = 0; total_size=0;
         s_flag=1;
         for (i = 0; i < n1_op->incnt; i++)
         {
            if (avail_size == 0)
            {
               require_size = dlen - total_size;
               buf_size = (require_size >= SCATTER_CHUNK)?SCATTER_CHUNK:require_size;
               buffer = get_buffer_from_pool (n1_dev, buf_size);
               if (buffer == NULL)
               {
                  cavium_error("scatter buffer allocation failed\n");
                  ret = 1;
                  goto do_op_clean;
               }
               if (slist_cnt != 0)
                  user_info->slist_ptrsize[slist_cnt-1] = used_size;
               avail_size = buf_size;
               used_size = 0;
               user_info->slist_ptr[slist_cnt] = buffer;
               slist_cnt++;
            }
            if (n1_op->insize[i] <= avail_size) {
               if(cavium_copy_in(&buffer[used_size],
                             CAST_FRM_X_PTR(n1_op->inptr[i]),
                              n1_op->insize[i]))
               {
                  cavium_error("Failed to copy in user buffer=%d, size=%d\n",
                                i,n1_op->insize[i]);
                  ret = 1;
                  goto do_op_clean;
               }
               if (n1_op->inunit[i] == UNIT_64_BIT)
               {
                  p = (Uint64 *)&buffer[used_size];
                  *p = htobe64(*p);
               }
               used_size += n1_op->insize[i];
               avail_size -= n1_op->insize[i];
               total_size += n1_op->insize[i];
            }
            else { /* insize[i] may have larger than scatter_chunk */
               Uint32 sin_size = n1_op->insize[i];
               Uint32 insize_used = 0, insize_req = 0;
               while (insize_used != n1_op->insize[i]) {
                   if (avail_size == 0)
                   {
                      require_size = dlen - total_size;
                      buf_size = (require_size >= SCATTER_CHUNK)?SCATTER_CHUNK:require_size;
                      buffer = get_buffer_from_pool (n1_dev, buf_size);
                      if (buffer == NULL)
                      {
                         cavium_error("scatter buffer allocation failed\n");
                         ret = 1;
                         goto do_op_clean;
                      }
                      if (slist_cnt != 0)
                         user_info->slist_ptrsize[slist_cnt-1] = used_size;

                      avail_size = buf_size;
                      used_size = 0;
                      user_info->slist_ptr[slist_cnt] = buffer;
                      slist_cnt++;
                   }
                   insize_req = (sin_size >= avail_size)?avail_size:sin_size;
                   if(cavium_copy_in(&buffer[used_size],
                                 CAST_FRM_X_PTR((Uint8*)
                                 ((unsigned long)n1_op->inptr[i]+insize_used)),
                                 insize_req))
                   {
                      cavium_error("Failed to copy in user buffer=%d, size=%d\n",
                                    i,n1_op->insize[i]);
                      ret = 1;
                      goto do_op_clean;
                   }
                   if (n1_op->inunit[i] == UNIT_64_BIT)
                   {
                      p = (Uint64 *)&buffer[used_size];
                      *p = htobe64(*p);
                   }
                   insize_used += insize_req;
                   sin_size -= insize_req;
                   avail_size -= insize_req;
                   used_size += insize_req;
                   total_size += insize_req;
                }
            }
         }
         if (slist_cnt != 0)
            user_info->slist_ptrsize[slist_cnt-1] = used_size;
         if (dlen != total_size){
            cavium_error ("Missing some thing in copying buffers deln: %d, total_size: %d\n", dlen, total_size);
            goto do_op_clean;
         }
         user_info->slist_cnt=slist_cnt;
      }
      else
      {
        in_buffer = get_buffer_from_pool(n1_dev, dlen);
        if (in_buffer == NULL)
        {
           cavium_error(" In buffer allocation failure\n");
           ret = 1;
           goto do_op_clean;
        }

        total_size = 0;
        for (i = 0; i < n1_op->incnt; i++)
        {
        if(cavium_copy_in(&in_buffer[total_size],
                              CAST_FRM_X_PTR(n1_op->inptr[i]),
                               n1_op->insize[i]))
         {
            cavium_error("Failed to copy in user buffer=%d, size=%d\n",
                          i,n1_op->insize[i]);
            ret = 1;
            goto do_op_clean;
         }
         if (n1_op->inunit[i] == UNIT_64_BIT)
         {
            p = (Uint64 *)&in_buffer[total_size];
            *p = htobe64(*p);
         }
         total_size += n1_op->inoffset[i];
      }
      }
   }
   user_info->sflag=s_flag;
   if (rlen)
   {
      if (n1_op->dma_mode==CAVIUM_SCATTER_GATHER && rlen > SCATTER_THOLD)
      {
         Uint8 *buffer = NULL;
         Uint32 mod_size;
         g_flag=1;
         glist_cnt = (rlen/SCATTER_CHUNK);
         for (i=0; i<glist_cnt; i++) {
            buffer = get_buffer_from_pool(n1_dev, SCATTER_CHUNK);
            if (buffer == NULL)
            {
               cavium_print ("Gather list buffer allocation failed\n");
               ret = 1;
               goto do_op_clean;
            }
            user_info->glist_ptr[i] = buffer;
            user_info->glist_ptrsize[i] = SCATTER_CHUNK;
         }
         mod_size = rlen%SCATTER_CHUNK;
         if (mod_size)
         {
            buffer = get_buffer_from_pool(n1_dev, mod_size);
            if (buffer == NULL)
            {
               cavium_print ("Gather list buffer allocation failed\n");
               ret = 1;
               goto do_op_clean;
            }
            user_info->glist_ptr[i] = buffer;
            user_info->glist_ptrsize[i] = mod_size-8;
            glist_cnt++;
         }
         user_info->glist_cnt=glist_cnt;
      }
      else
      {
        out_buffer = get_buffer_from_pool(n1_dev, rlen);
        if (out_buffer == NULL)
        {
          cavium_print(" Out buffer allocation failure\n");
          ret = 1;
          goto do_op_clean;
        }
#ifdef DUMP_FAILING_REQUESTS
      memset(out_buffer, 0xa5, rlen);
#endif
      if (n1_op->dma_mode == CAVIUM_SCATTER_GATHER)
      {
         total_size=0;
         for(i=0;i<n1_op->outcnt;i++)
         {
            total_size += n1_op->outoffset[i];
         }
      }
      }

   }
   user_info->gflag=g_flag;

   /* Build user info buffer */
   user_info->req_type = n1_op->req_type;
   user_info->n1_dev=n1_dev;
   user_info->dma_mode= n1_op->dma_mode;
   user_info->rlen=rlen;
   user_info->dlen=n1_op->dlen;
   if (s_flag)
      user_info->in_buffer = user_info->slist_ptr[0];
   else
      user_info->in_buffer = in_buffer;
   if (g_flag)
      user_info->out_buffer = user_info->glist_ptr[0];
   else
      user_info->out_buffer = out_buffer;
   user_info->in_size = dlen;
   user_info->out_size = rlen;
   user_info->pid = cavium_get_pid();
   user_info->signo = CAVIUM_SIGNAL_NUM;

   /* user mode pointers and request buffer*/
   user_info->outcnt = n1_op->outcnt;
   for (i = 0; i < user_info->outcnt; i++)
   {
      user_info->outptr[i] = CAST_FRM_X_PTR(n1_op->outptr[i]);
      user_info->outsize[i] = n1_op->outsize[i];
      user_info->outoffset[i] = n1_op->outoffset[i];
      user_info->outunit[i] = n1_op->outunit[i];
   }
   if (g_flag)
         req_compl_addr = (volatile Uint64 *)((ptrlong)user_info->glist_ptr[glist_cnt-1] + user_info->glist_ptrsize[glist_cnt-1]);
      else
      {
#ifdef MC2
         req_compl_addr = (volatile Uint64 *)((ptrlong)out_buffer + n1_op->rlen);
#else
         req_compl_addr = (volatile Uint64 *)((ptrlong)out_buffer + rlen-8);
#endif
         cavium_dbgprint("do_operation: blocking call: rptr=0x%p\n", user_info->out_buffer);
      }
   *req_compl_addr=COMPLETION_CODE_INIT;
   user_info->completion_addr=req_compl_addr;
   user_info->opcode=n1_op->opcode;

/* Submit command to the chip */
 
   cmd=(Cmd *)&request.cmd; 
   cmd->opcode=htobe16(n1_op->opcode);
   cmd->size= htobe16(n1_op->size);
   cmd->param=htobe16(n1_op->param);
   cmd->dlen=htobe16(dlen);
   user_info->dptr=user_info->in_buffer;
   if(dlen)
   {
     if (cavium_debug_level > 2)
       cavium_dump("dptr", user_info->dptr, user_info->dlen);
       user_info->dptr_baddr=(Uint64)(cavium_map_kernel_buffer(n1_dev,
                              (void *)user_info->dptr, 
                              user_info->dlen, 
                              CAVIUM_PCI_DMA_BIDIRECTIONAL));;
       cavium_flush_cache(n1_dev,
                user_info->dlen,
                user_info->dptr,
                user_info->dptr_baddr,
                CAVIUM_PCI_DMA_BIDIRECTIONAL);
     
   }else
     request.dptr=0; 
  user_info->rptr=user_info->out_buffer;
  if(rlen)
     user_info->rptr_baddr=(Uint64)(cavium_map_kernel_buffer(n1_dev,(void *)user_info->rptr,n1_op->rlen+sizeof(Uint64), CAVIUM_PCI_DMA_BIDIRECTIONAL));
  else
    request.rptr=0;
    cavium_flush_cache(n1_dev,
            COMPLETION_CODE_SIZE,
            (ptrlong)req_compl_addr,
            (user_info->rptr_baddr+n1_op->rlen),
            CAVIUM_PCI_DMA_BIDIRECTIONAL);
   
{
      offset=n1_op->ctx_ptr&0x7FF;
      n1_op->ctx_ptr=n1_op->ctx_ptr&~(0x7FF);
      if(n1_op->ctx_ptr)      
          request.cptr = ((struct ctx_addr *)(CAST_FRM_X_PTR(n1_op->ctx_ptr)))->phy_addr;
      else
          request.cptr = (Uint64)0;
 }
       
   request.cptr = htobe64((request.cptr+offset));
   request.rptr = htobe64((user_info->rptr_baddr));
   request.dptr = htobe64((user_info->dptr_baddr));

   if (n1_op->req_type == CAVIUM_BLOCKING)
   {
      cavium_get_channel(&user_info->channel);
   }
   /* Request id is sent to the application */
   user_info->status=ERR_REQ_PENDING;
   if(max_q)
   {
      queue = n1_dev->curr_q;
      n1_dev->curr_q = (n1_dev->curr_q + 1) % n1_dev->max_queues;
      
   }
   else
   if (!n3_vf_driver)
      queue=smp_processor_id()%n1_dev->max_queues;
   else {
       queue = test_queue;
       test_queue++; 
       if (test_queue >= n1_dev->max_queues)
               test_queue = 0;
   }  
find_command_block_again:
   cavium_spin_lock_softirqsave(&(n1_dev->pending_queue[queue].pending_lock));   
   cmd_data=(CMD_DATA *)(&((n1_dev->pending_queue[queue].cmd_queue)[n1_dev->pending_queue[queue].queue_rear]));
   if(!cmd_data->free) //pending queue full
   {   
       cavium_dbgprint("Pending queue %d full \n",queue);
       cavium_spin_unlock_softirqrestore(&(n1_dev->pending_queue[queue].pending_lock)); 
       free_pending_queue(queue, 10,n1_dev); 
       goto find_command_block_again;
   }
   if(!cmd_data->free) {
      cavium_spin_unlock_softirqrestore(&(n1_dev->pending_queue[queue].pending_lock)); 
      ret = 1;
      goto do_op_clean;
   }
   index=n1_dev->pending_queue[queue].queue_rear;
   n1_dev->pending_queue[queue].queue_rear++;
   if(n1_dev->pending_queue[queue].queue_rear == n1_dev->pending_queue[queue].queue_size)
        n1_dev->pending_queue[queue].queue_rear=0;
   cmd_data->cb=CAST_FRM_X_PTR(NULL);
   cmd_data->cb_arg=CAST_FRM_X_PTR(NULL);
   cmd_data->completion_addr=user_info->completion_addr;
   cmd_data->post_arg=(void *)user_info;
   cmd_data->free=0;
   cmd_data->is_user=1;
   cmd_data->done=0;
   user_info->status=0xFF;
   user_info->cmd_data=cmd_data;
   user_info->queue= queue;
   user_info->index=index;
   user_info->n1_dev = n1_dev;
   cavium_spin_unlock_softirqrestore(&(n1_dev->pending_queue[queue].pending_lock));   
  user_info->time_in = cavium_jiffies;
  send_command(n1_dev,&request,queue, n1_op->ucode_idx,(Uint64*)(ptrlong)req_compl_addr);
 
   if (n1_op->req_type == CAVIUM_BLOCKING)
   {

      while (*(req_compl_addr)==COMPLETION_CODE_INIT)
      {
#ifdef SLOW_CPU
         cavium_yield(&(user_info->channel),(10*CAVIUM_HZ)/1000);
#else
         cavium_wait_interruptible_timeout(user_info->channel,
         ((Uint8)(*req_compl_addr >> COMPLETION_CODE_SHIFT)!=0xFF),10);
#endif
        if((*(req_compl_addr) == COMPLETION_CODE_INIT) && ((user_info->time_in+cavium_command_timeout)<=(Uint64)cavium_jiffies )){
                ret=ERR_REQ_TIMEOUT;
                break;
        }
      }
      if(user_info->status){
         cavium_spin_lock_softirqsave(&(n1_dev->pending_queue[queue].pending_lock));   
         cmd_data->done=1;
         cavium_spin_unlock_softirqrestore(&(n1_dev->pending_queue[queue].pending_lock));   
       }
      cavium_invalidate_cache(n1_dev,COMPLEION_CODE_SIZE, 
                         (ptrlong)user_info->completion_addr,
                         (ptrlong)(user_info->rptr_baddr+user_info->rlen), 
                         CAVIUM_PCI_DMA_BIDIRECTIONAL);
     ret = *((Uint8 *)req_compl_addr);
     user_info->status=ret;
     user_info->cmd_data= NULL;
     do_post_process(n1_dev, user_info);
     return ret;
do_op_clean:
   if (!mapped)
   {
      for (i = 0; i < slist_cnt; i++)
         put_buffer_in_pool ( user_info->slist_ptr[i],user_info->slist_ptrsize[i]);
      for (i = 0; i < glist_cnt; i++)
         put_buffer_in_pool (user_info->glist_ptr[i],user_info->glist_ptrsize[i]);
   }
   if (in_buffer && !mapped)
      put_buffer_in_pool((Uint8 *)in_buffer,dlen);
   if (out_buffer && !mapped)
       put_buffer_in_pool((Uint8 *)out_buffer,rlen);
   if (user_info)
       put_buffer_in_pool((Uint8 *)user_info,sizeof(n1_user_info_buffer));
   }
   else
   {
      ret = ERR_REQ_PENDING;
   }

   return ret;
}

/*
 * do_speed() function to test the performance of device
 *
 * Fill maximum no. of requests in command queue then call ring_door_bell(),
 * then calculate the result for (no. of devices *command_queue_max) requests
 *
 * or according to time given in cavium_speed_timeout (default 0 seconds).
 *
 * If time is 0 seconds then
 * calculate the result for (no. of devices * command_queue_max) requests.
 *
 */


int
do_speed(cavium_device *n1_dev, n1_request_buffer *n1_req)
{
    Uint32 speed_dev_count = 0;
    Uint32 dlen, rlen;
    Uint8 *in_buffer[MAX_DEV], **out_buffer[MAX_DEV] ;
    Uint64 *p;
    Uint64 *out_buffer_phys[MAX_DEV];
    Uint64 in_buffer_phys[MAX_DEV];
    int total_size, ret = 0;
    Request *request[MAX_DEV];
    Cmd *strcmd = NULL;
    Uint64 **comp_addr[MAX_DEV];
    int offset=0;
    volatile Uint8* cmp;
    Uint64 start_time = 0, end_time = 0, total_time = 0;
    Uint32 i = 0, j = 0, k = 0, count[] = {0,0,0,0}, l[] = {0,0,0,0};
    Uint32 no_req = 0;
    Uint64 dataptr = 0, recvptr = 0;
    Speed_Test_Info *info = NULL;
    Uint8 *user_info = NULL;
    Uint32 CHUNK_SIZE = 0;
    struct MICROCODE *microcode =NULL;
    cavium_dbgprint ("do_speed called\n");

#define CAVIUM_COMMAND_QUEUE_SIZE    cavium_dev[0].command_queue_max

    speed_dev_count = dev_count;

    CHUNK_SIZE = CAVIUM_COMMAND_QUEUE_SIZE;

    dlen = n1_req->dlen;
    rlen = ROUNDUP8(n1_req->rlen + 8);
    /* Locate appropriate buffer to store the speed result
     *  structure in outptr list */
    for (k=0; k <n1_req->outcnt; k++) {
      if (n1_req->outsize[k] >= sizeof(info))
      {
         user_info = CAST_FRM_X_PTR(n1_req->outptr[k]);
         break;
      }
    }
    if (k == n1_req->outcnt) /* if no buffer exists */
    {
       cavium_dbgprint ("No Sufficient buffer availble in outptr list\n");
       return ERR_OPERATION_NOT_SUPPORTED;
    }
 
 
    for(k = 0; k < speed_dev_count; k++)
    {
       if (dlen)
       {
          in_buffer[k] = get_buffer_from_pool(&cavium_dev[k], dlen);
          if (in_buffer[k] == NULL)
          {
             cavium_error(" In buffer allocation failure\n");
             ret = 1;
             goto do_speed_clean;
          }
          total_size = 0;
          for (i = 0; i < n1_req->incnt; i++)
          {
             if(cavium_copy_in(&in_buffer[k][total_size],                                                 CAST_FRM_X_PTR(n1_req->inptr[i]), n1_req->insize[i]))
             {
                cavium_error("Failed to copy in user buffer=%d, size=%d\n",
                          i,n1_req->insize[i]);
                ret = 1;
                goto do_speed_clean;
             }
             if (n1_req->inunit[i] == UNIT_64_BIT)
             {
                p = (Uint64 *)&in_buffer[k][total_size];
                *p = htobe64(*p);
             }
             total_size += n1_req->inoffset[i];
          }
       }
    }

    n1_req->dlen = (Uint16) dlen;
    offset=n1_req->ctx_ptr&0x7FF;
    n1_req->ctx_ptr=n1_req->ctx_ptr&~(0x7FF); 
    if(n1_req->ctx_ptr)      
      n1_req->ctx_ptr = ((struct ctx_addr *)(CAST_FRM_X_PTR(n1_req->ctx_ptr)))->phy_addr;
      else
          n1_req->ctx_ptr = (Uint64)0;
     n1_req->ctx_ptr+=offset;
    for(k = 0; k < speed_dev_count; k++)
    {
       n1_req->inptr[0] = CAST_TO_X_PTR(in_buffer[k]);
       request[k] = (Request *) get_buffer_from_pool(&cavium_dev[k], sizeof(Request));
       if (request[k] == NULL)
       {
          cavium_error("OOM for request allocation \n");
          ret = 1;
          goto do_speed_clean;
       }
 
       comp_addr[k] = (Uint64 **) get_buffer_from_pool(&cavium_dev[k], CAVIUM_COMMAND_QUEUE_SIZE * sizeof(Uint64 *));
       if(comp_addr[k] == NULL)
       {
          cavium_error("OOM for comp_addr allocation \n");
          ret =1;
          goto do_speed_clean;
       }
 
       strcmd = (Cmd *)(request[k]);
       strcmd->opcode = htobe16(n1_req->opcode);
       strcmd->size = htobe16(n1_req->size);
       strcmd->param = htobe16(n1_req->param);
       strcmd->dlen = htobe16(n1_req->dlen);
 
       /* Setup dptr */
       if (n1_req->dlen)
          dataptr = (Uint64) cavium_map_kernel_buffer(&cavium_dev[k],
                                               in_buffer[k] ,n1_req->dlen,
                                               CAVIUM_PCI_DMA_BIDIRECTIONAL);
       else
          dataptr = 0;
       in_buffer_phys[k] = dataptr;
 
       (request[k])->dptr = htobe64(dataptr);
 
       out_buffer[k] = (Uint8 **) get_buffer_from_pool(&cavium_dev[k],
                                  CAVIUM_COMMAND_QUEUE_SIZE * sizeof(Uint8 *));
       out_buffer_phys[k] = (Uint64 *) get_buffer_from_pool(&cavium_dev[k],
                                  CAVIUM_COMMAND_QUEUE_SIZE * sizeof(Uint64));
       if(out_buffer[k] == NULL||out_buffer_phys[k] == NULL)
       {
          cavium_print(" OOM for out_buffer\n");
          ret =1;
          goto do_speed_clean;
       }
 
       for(i=0; i< CAVIUM_COMMAND_QUEUE_SIZE; i++){
          if (rlen)
          {
             out_buffer[k][i] = get_buffer_from_pool(&cavium_dev[k], rlen);
             if (out_buffer[k][i] == NULL)
             {
                cavium_print(" Out buffer allocation failure\n");
                ret = 1;
                goto do_speed_clean;
             }
             memset(out_buffer[k][i], 0, rlen);
             recvptr = (Uint64) cavium_map_kernel_buffer(&cavium_dev[k], 
                                      out_buffer[k][i] ,
                                      n1_req->rlen + sizeof(Uint64),
                                      CAVIUM_PCI_DMA_BIDIRECTIONAL);
             out_buffer_phys[k][i] = recvptr;
 
            comp_addr[k][i] = (Uint64 *)((Uint8 *)out_buffer[k][i] + n1_req->rlen);
           *comp_addr[k][i] = COMPLETION_CODE_INIT;
          }else
             (request[k])->rptr = 0ull;
       }
       if (n1_req->ctx_ptr)
             (request[k])->cptr = htobe64(n1_req->ctx_ptr);
          else
             (request[k])->cptr = 0;
          if (nplus || ssl > 0 || ipsec > 0) {
             if( cavium_dev[k].device_id == NPX_DEVICE|| cavium_dev[k].device_id == N3_DEVICE)
             {
                 microcode = &(cavium_dev[k].microcode[n1_req->ucode_idx]);
#if __CAVIUM_BYTE_ORDER == __CAVIUM_BIG_ENDIAN
          /* Bits 62-61 of cptr store the queue index. */
                request[k]->cptr |= (((Uint64)(microcode->core_grp)) << 61);
#else
          /* Bits 6-5 of the last byte (MSB) of cptr stores the queue index. */
                request[k]->cptr |= (((Uint64)microcode->core_grp) << 5);
#endif
             }
          }
     }
 
    for(k = 0; k < speed_dev_count; k++){
       lock_command_queue(&cavium_dev[k], n1_req->req_queue);
       for(i=0; i< CAVIUM_COMMAND_QUEUE_SIZE; i++)
       {
          /* Setup cptr */
             (request[k])->rptr = htobe64(out_buffer_phys[k][i]);
             cavium_memcpy((Uint8 *)
                     (cavium_dev[k].command_queue_front[n1_req->req_queue]),
                     (Uint8 *)(request[k]),COMMAND_BLOCK_SIZE);
             inc_front_command_queue(&cavium_dev[k], n1_req->req_queue);
       }
    }

    start_time = cavium_rdtsc();
    while(1)
    {
       for(k = 0; k < speed_dev_count; k++)
       {
             count[k] = CHUNK_SIZE;
          ring_door_bell(&cavium_dev[k], n1_req->req_queue, count[k]);
       }
       for(k = 0; k < speed_dev_count; k++)
       {
          for(j = 0; j < count[k]; j++, l[k]++)
          {
             cmp = (volatile Uint8 *)(comp_addr[k][l[k]]);
 
                while(*cmp == 0xff)
                cavium_udelay(100);
 
              *comp_addr[k][l[k]] = COMPLETION_CODE_INIT;
          }
          no_req += count[k];
          if( l[k] == CAVIUM_COMMAND_QUEUE_SIZE)
          {
             l[k] = 0;
             if(no_req >= (speed_dev_count * CAVIUM_COMMAND_QUEUE_SIZE))
             {
                Uint32 divisor;
                Uint64 time_diff;
 
                end_time =  cavium_rdtsc();
                time_diff = end_time - start_time;
                divisor = cavium_speed_unit()/1000;
                /* If time_diff is greater than 32 bit */
                if (time_diff > 0xFFFFFFFF)  {
                   Uint32 t1, t2;
                   Uint32 low_4B, high_4B; /* Lower & Higher 4 Bytes */
                   Uint32 shift_cnt = 32;
 
                   low_4B = time_diff & 0xFFFFFFFF; /* Least 32 bit */
                   high_4B = time_diff >> shift_cnt; /* Remaining bits */
 
                   while (1){ /* make high_4B to 32b length */
                      if (high_4B & 0x80000000) break;
                      else {
                         high_4B <<= 1;
                         shift_cnt-=1;
                      }
                   }
                   t1 = high_4B/divisor;
                   t2 = low_4B/divisor;
                   total_time += (Uint64)((t1<<shift_cnt)+t2);
                }
                else
                   total_time += ((Uint32)time_diff/divisor);
 
                start_time = end_time;
 
                if((total_time)>=(((Uint64)(cavium_speed_timeout)*1000000)))
                   goto timeout;
             }
          }
       }
    }

timeout:
    for(k = 0;k<speed_dev_count; k++)
    {
       cavium_dev[k].door_bell_count[n1_req->req_queue] = 0;
       unlock_command_queue(&cavium_dev[k], n1_req->req_queue);
    }
 
    info = (Speed_Test_Info *) get_buffer_from_pool(&cavium_dev[0],sizeof(Speed_Test_Info));
    if (info == NULL)
    {
       cavium_error(" OOM for info buffer allocation \n");
       ret = 1;
       goto do_speed_clean;
    }
    info->time_taken = total_time;    /* microseconds */
    info->req_completed = no_req;
    info->dlen = dlen;
    info->rlen = rlen;
 
    if(cavium_copy_out(user_info, (info), sizeof(Speed_Test_Info)))
    {
       cavium_error("Failed to copy out to user \n");
       ret = 1;
       goto do_speed_clean;
    }


do_speed_clean:
    if(info)
       put_buffer_in_pool((Uint8 *)info,sizeof(Speed_Test_Info));
     for(k = 0; k < speed_dev_count; k++)
     {
       if(comp_addr[k])
          put_buffer_in_pool((Uint8 *)comp_addr[k],CAVIUM_COMMAND_QUEUE_SIZE*sizeof(Uint64 *));
       if(request[k])
          put_buffer_in_pool((Uint8 *)request[k],sizeof(Request));
       if (in_buffer[k])
       {
          cavium_unmap_kernel_buffer(&cavium_dev[k],in_buffer_phys[k],n1_req->dlen, 
                                      CAVIUM_PCI_DMA_BIDIRECTIONAL);
          put_buffer_in_pool((Uint8 *)in_buffer[k],dlen);
       }
 
 
       for(i = 0; i < CAVIUM_COMMAND_QUEUE_SIZE; i++){
         cavium_unmap_kernel_buffer(&cavium_dev[k],out_buffer_phys[k][i],n1_req->rlen+sizeof(Uint64),
                                  CAVIUM_PCI_DMA_BIDIRECTIONAL);
          put_buffer_in_pool((Uint8 *) out_buffer[k][i],rlen);
       }
       if(out_buffer[k])
          put_buffer_in_pool((Uint8 *) out_buffer[k], CAVIUM_COMMAND_QUEUE_SIZE*sizeof(Uint8 *));
       if(out_buffer_phys[k])
          put_buffer_in_pool((Uint8 *) out_buffer_phys[k], CAVIUM_COMMAND_QUEUE_SIZE*sizeof(Uint64));
    }
    cavium_dbgprint ("do_speed return\n");
    return ret;
}


/*
 * Callback function to scatter result to user space pointers.
 */
void flush_queue(cavium_device *n1_dev, int queue)
{
    MPRINTFLOW();
    lock_command_queue(n1_dev, queue);
    ring_door_bell(n1_dev, queue, n1_dev->door_bell_count[queue]);
    n1_dev->door_bell_count[queue]=0;
    unlock_command_queue(n1_dev, queue);
}

/*
 * $Id: request_manager.c,v 1.54 2011/05/11 14:34:12 tghoriparti Exp $
 */
