/* cavium_proc.c*/
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
 * EITHER EXPRESS,IMPLIED,STATUTORY, OR OTHERWISE, WITH RESPECT TO THE SOFTWARE, * INCLUDING ITS CONDITION,ITS CONFORMITY TO ANY REPRESENTATION OR DESCRIPTION,
 * OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM SPECIFICALLY
 * DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE, MERCHANTABILITY,
 * NONINFRINGEMENT,FITNESS FOR A PARTICULAR PURPOSE,LACK OF VIRUSES, ACCURACY OR * COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE TO
 * DESCRIPTION. THE ENTIRE RISK ARISING OUT OF USE OR PERFORMANCE OF THE
 * SOFTWARE LIES WITH YOU.
 *
 */

#include <cavium_sysdep.h>
#include <cavium_common.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/module.h>
#include <asm/errno.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include "cavium_list.h"
#include "cavium.h"
#include "linux_main.h"
#include "init_cfg.h"
#include "buffer_pool.h"

extern int n3_vf_driver;
struct proc_dir_entry    *cavium_dir;
static struct proc_dir_entry    *debug_level_file,
	    *speed_timeout_file,
            *timeout_file,
            *version_file,
#ifdef COUNTER_ENABLE
            *data_stats_file,
            *data_stats_reset_file,
#endif
#ifndef CTX_MEM_IS_HOST_MEM
            *contextStats_file,
#endif

            *keymemStats_file,
            *cmdquelocation_file,
            *reg_file;

extern int cavium_speed_timeout;

int cavium_debug_level=0;
#ifdef COUNTER_ENABLE
int cavium_data_stats_reset=0;
#endif
Uint64 get_next_addr(cavium_device *pkp_dev, int q_no);
extern Uint32 fsk_mem_chunk_count[MAX_DEV];
extern Uint32 ex_key_mem_chunk_count[MAX_DEV];
extern Uint32 host_key_mem_chunk_count[MAX_DEV];
extern int dev_count;
extern short ssl, ipsec;
extern int ssl_cores, ipsec_cores;
extern cavium_device cavium_dev[];
extern Uint32 cavium_command_timeout;
#ifndef CTX_MEM_IS_HOST_MEM
extern Uint32 allocated_context_count;
#endif
extern Uint8 cavium_version[3];

#ifdef COUNTER_ENABLE
 extern Uint32 hmac_count;
 extern Uint32 encrypt_count;
 extern Uint32 decrypt_count;
 extern Uint32 encrypt_record_count;
 extern Uint32 decrypt_record_count;
 extern Uint32 ipsec_inbound_count;
 extern Uint32 ipsec_outbound_count;
 extern Uint64 bytes_in_enc;
 extern Uint64 bytes_out_enc;
 extern Uint64 bytes_in_dec;
 extern Uint64 bytes_out_dec;
 extern Uint64 bytes_in_rec_enc;
 extern Uint64 bytes_out_rec_enc;
 extern Uint64 bytes_in_rec_dec;
 extern Uint64 bytes_out_rec_dec;
 extern Uint64 bytes_in_hmac;
 extern Uint64 bytes_out_hmac;
 extern Uint64 bytes_in_ipsec_ib;
 extern Uint64 bytes_out_ipsec_ib;
 extern Uint64 bytes_in_ipsec_ob;
 extern Uint64 bytes_out_ipsec_ob;
 extern Uint32 enc_pkt_err;
 extern Uint32 dec_pkt_err;
 extern Uint32 enc_rec_pkt_err;
 extern Uint32 dec_rec_pkt_err;
 extern Uint32 in_ipsec_pkt_err;
 extern Uint32 out_ipsec_pkt_err;
 extern Uint32 hmac_pkt_err;
#endif



static int
proc_write_timeout(struct file *file, const char *buffer,
             unsigned long count, void *data)
{
   char str[count+1], *strend;
   Uint32 timeout;

   CAVIUM_MOD_INC_USE_COUNT;

   if(cavium_copy_in(str, buffer, count))
   {
      cavium_error("cavium_copy_out failed\n");
      return -EFAULT;
   }
   str[count] = '\0';

   timeout = simple_strtoul(str, &strend, 0);
   if (timeout > (2*60*60))
   {
      cavium_error("Timeout too high. The maximum value is 7200\n");
      return -EFAULT;
   }
   cavium_command_timeout = timeout*HZ;

   CAVIUM_MOD_DEC_USE_COUNT;

   return count;
}

static int
proc_read_timeout(char *page, char **start, off_t off, int count,
            int *eof, void *data)
{
   int len = 0;

   CAVIUM_MOD_INC_USE_COUNT;

   len = sprintf(page + len, "%d\n", (cavium_command_timeout/HZ));

   CAVIUM_MOD_DEC_USE_COUNT;

   return len;
}


static int
proc_write_debug_level(struct file *file, const char *buffer,
             unsigned long count, void *data)
{
   char str[count+1], *strend;

   CAVIUM_MOD_INC_USE_COUNT;

   if(cavium_copy_in(str, buffer, count))
   {
      cavium_error("cavium_copy_out failed\n");
      return -EFAULT;
   }
   str[count] = '\0';

   cavium_debug_level = simple_strtoul(str, &strend, 0);

   CAVIUM_MOD_DEC_USE_COUNT;

   return count;
}

static int
proc_read_debug_level(char *page, char **start, off_t off, int count,
            int *eof, void *data)
{

   int len=0;
   CAVIUM_MOD_INC_USE_COUNT;
   len = sprintf(page + len, "%d\n", cavium_debug_level);
   CAVIUM_MOD_DEC_USE_COUNT;
   return len;
}

static int
proc_write_speed_timeout(struct file *file, const char *buffer,
             unsigned long count, void *data)
{
   char str[count+1], *strend;

   CAVIUM_MOD_INC_USE_COUNT;
   
   if(cavium_copy_in(str, buffer, count))
   {
      cavium_error("cavium_copy_out failed\n");
      return -EFAULT;
   }
   str[count] = '\0';

   cavium_speed_timeout = simple_strtoul(str, &strend, 0);

   CAVIUM_MOD_DEC_USE_COUNT;

   return count;
}


static int
proc_read_speed_timeout(char *page, char **start, off_t off, int count,
            int *eof, void *data)
{

   int len=0;
   CAVIUM_MOD_INC_USE_COUNT;
   len = sprintf(page + len, "%d\n", cavium_speed_timeout);
   CAVIUM_MOD_DEC_USE_COUNT;
   return len;
}


#ifdef COUNTER_ENABLE
static int
proc_write_data_stats_reset(struct file *file, const char *buffer,
             unsigned long count, void *data)
{
   char str[count+1], *strend;

   CAVIUM_MOD_INC_USE_COUNT;

   if(cavium_copy_in(str, buffer, count))
   {
      cavium_error("cavium_copy_out failed\n");
      return -EFAULT;
   }
   str[count] = '\0';

   cavium_data_stats_reset = simple_strtoul(str, &strend, 0);

 if(cavium_data_stats_reset) { 
    hmac_count =0;
    encrypt_count=0;
    decrypt_count=0;
    encrypt_record_count=0;
    decrypt_record_count=0;
    ipsec_inbound_count=0;
    ipsec_outbound_count=0;
    bytes_in_rec_enc=0;
    bytes_out_rec_enc=0;
    bytes_in_rec_dec=0;
    bytes_out_rec_dec=0;
    bytes_in_enc =0;
    bytes_out_enc =0;
    bytes_in_dec =0;
    bytes_out_dec =0;
    bytes_in_hmac =0;
    bytes_out_hmac =0;
    bytes_in_ipsec_ib =0;
    bytes_out_ipsec_ib =0;
    bytes_in_ipsec_ob =0;
    bytes_out_ipsec_ob =0;
    enc_pkt_err =0;
    dec_pkt_err=0;
    enc_rec_pkt_err =0;
    dec_rec_pkt_err =0;
    in_ipsec_pkt_err =0;
    out_ipsec_pkt_err =0;
    hmac_pkt_err =0;
    }
    cavium_data_stats_reset=0;
   
   CAVIUM_MOD_DEC_USE_COUNT;

   return count;
}

static int
proc_read_data_stats_reset(char *page, char **start, off_t off, int count,
            int *eof, void *data)
{

   int len=0;
   CAVIUM_MOD_INC_USE_COUNT;
   len = sprintf(page + len, "%d\n", cavium_data_stats_reset);
   CAVIUM_MOD_DEC_USE_COUNT;
   return len;
}
#endif

static int cavium_proc_cmd_show(struct seq_file *m, void *v)
{
   Uint32 queue_location;
   Uint32 dwval =0;
   Uint32 dwval1 =0;
   cavium_device *ptr;
   int dev_no=0;
   int que_no=0;
     /* Increment the module usage counter */

   CAVIUM_MOD_INC_USE_COUNT;

   /* Get the value of the command queue pointer location
     for all the command queues */

   seq_printf(m,"\n\n #### The command queue pointer locations ####\n\n");

   for (dev_no=0; dev_no < dev_count; dev_no++)
   {
      if(cavium_dev[dev_no].enable)
      {
         ptr = &cavium_dev[dev_no];
         seq_printf(m, "---------- \n");
         seq_printf(m, "DEVICE : %d \n",dev_no);
         seq_printf(m, "---------- \n");

       //  if(ptr->device_id==NPX_DEVICE)
         {
	     seq_printf(m, "#### Device Read Pointer Locations #### \n\n");
             for (que_no = 0; que_no < ptr->max_queues ; que_no++)
             {
                dwval = 0;
               if(ptr->device_id == NPX_DEVICE){    
                read_PKP_register(ptr, (ptr->CSRBASE_A + 0x208+ (que_no * 0x10)
), &dwval);
                read_PKP_register(ptr, (ptr->CSRBASE_B + REQ0_BASE_LOW + (que_no *0x20) ), &dwval1);
                dwval= (dwval-dwval1)/COMMAND_BLOCK_SIZE;
               }else if(ptr->device_id == N3_DEVICE){
                   Uint64 read=0ULL;
                   Uint8 *rptr=NULL;
                   read = get_next_addr(ptr,que_no);
                   rptr = bus_to_virt(read);
                   dwval=(Uint32)(rptr-((Uint8 *)(ptrlong)ptr->command_queue_base[que_no])); 
                   dwval=dwval/COMMAND_BLOCK_SIZE; 
               }
               seq_printf(m, "Queue %d : queue location : %d\n\n",que_no,dwval);
            }
         }
         seq_printf(m, "#### Host Write Pointer Locations #### \n\n");
         for (que_no = 0; que_no < ptr->max_queues ; que_no++)
         {

            /* Get the difference in the address of the command_queue_front pointer and the command_queue_base pointer */

             queue_location = cavium_dev[dev_no].command_queue_front[que_no] - cavium_dev[dev_no].command_queue_base[que_no];
             queue_location = queue_location / COMMAND_BLOCK_SIZE;
             seq_printf(m,"Queue %d : queue location : %d\n\n",que_no,queue_location);
         }
      }
   }

   CAVIUM_MOD_DEC_USE_COUNT;

   return 0;
}

static int cavium_proc_version_show(struct seq_file *m, void *v)
{

   CAVIUM_MOD_INC_USE_COUNT;

   seq_printf(m, "Driver Version: %01d.%02d.%02d\n\n", cavium_version[0],cavium_version[1],cavium_version[2]);
   seq_printf(m, "Driver Compile time defines \n");
   seq_printf(m, "---------------------------- \n");
   if (ssl>=0) 
      seq_printf(m, "MAIN LINE PROTOCOL used : SSL\n");
   if(ipsec>0) 
      seq_printf(m, "MAIN LINE PROTOCOL used : IPSEC\n");

#ifdef MC2
   seq_printf(m, "MICROCODE used : MC2 \n\n");
#else  
   seq_printf(m, "MICROCODE used : MC1 \n\n");
#endif

   CAVIUM_MOD_DEC_USE_COUNT;
   return 0;

}

#ifndef CTX_MEM_IS_HOST_MEM

static int cavium_proc_context_show(struct seq_file *m, void *v)
{

   int i=0;

   /* Increment the module usage counter */

   CAVIUM_MOD_INC_USE_COUNT;

   /* Get the value of the initial context from the
   global array of initial key counters
   */

   seq_printf(m,"\n\n#### The initial count of the key memories allocated ####\n\n");

   for (i=0; i< dev_count ; i++)
   {
      if(cavium_dev[i].enable)
      {
         seq_printf(m, "---------- \n");
         seq_printf(m, "DEVICE : %d \n",i);
         seq_printf(page + len, "---------- \n");

          seq_printf(m,"Initial SRAM key memory chunk count --> %d\n\n",fsk_mem_chunk_count[i]);
          seq_printf(m,"Initial DRAM key memory chunk count --> %d\n\n",ex_key_mem_chunk_count[i]);
          seq_printf(m,"Initial Host key memory chunk count --> %d\n\n\n",host_key_mem_chunk_count[i]);
      }
   }

   seq_printf(m,"\n#### The Current count of the key memories allocated ####\n\n");

   for (i=0;i< dev_count ; i++)
    {
      if(cavium_dev[i].enable)
       {
         seq_printf(m, "---------- \n");
         seq_printf(m, "DEVICE : %d \n",i);
         seq_printf(m, "---------- \n");

          seq_printf(m,"Current SRAM key memory chunk allocated --> %d\n\n",cavium_dev[i].fsk_free_index);
          seq_printf(m,"Current SRAM key memory chunk remaining --> %d\n\n\n",cavium_dev[i].fsk_chunk_count - cavium_dev[i].fsk_free_index);
         seq_printf(m,"Current DRAM key memory chunk allocated --> %d\n\n",cavium_dev[i].ex_keymem_free_index );
         seq_printf(m,"Current DRAM key memory chunk remaining --> %d\n\n\n",cavium_dev[i].ex_keymem_chunk_count - cavium_dev[i].ex_keymem_free_index
);
         seq_printf(m,"Current Host key memory chunk allocated --> %d\n\n",cavium_dev[i].host_keymem_free_index );
         seq_printf(m,"Current Host key memory chunk remaining --> %d\n\n",cavium_dev[i].host_keymem_count - cavium_dev[i].host_keymem_free_index );
      }
   }

   CAVIUM_MOD_DEC_USE_COUNT;

   return 0;
}

#endif

static int cavium_proc_keymem_show(struct seq_file *m, void *v)
{
   int i=0;

   /* Increment the module usage counter */

   CAVIUM_MOD_INC_USE_COUNT;

   /* Get the value of the initial context from the
   global array of initial key counters
   */

   seq_printf(m,"\n\n#### The initial count of the key memories allocated ####\n\n");

   for (i=0; i< dev_count ; i++)
   {
      if(cavium_dev[i].enable)
      {
         seq_printf(m, "---------- \n");
         seq_printf(m, "DEVICE : %d \n",i);
         seq_printf(m, "---------- \n");
          seq_printf(m,"Initial SRAM key memory chunk count --> %d\n\n",fsk_mem_chunk_count[i]);
          seq_printf(m,"Initial DRAM key memory chunk count --> %d\n\n",ex_key_mem_chunk_count[i]);
          seq_printf(m,"Initial Host key memory chunk count --> %d\n\n\n",host_key_mem_chunk_count[i]);
      }
   }

   seq_printf(m,"\n#### The Current count of the key memories allocated ####\n\n");

   for (i=0;i< dev_count ; i++)
    {
      if(cavium_dev[i].enable)
       {
          seq_printf(m, "---------- \n");
          seq_printf(m, "DEVICE : %d \n",i);
          seq_printf(m, "---------- \n");

          seq_printf(m,"Current SRAM key memory chunk allocated --> %d\n\n",cavium_dev[i].fsk_free_index);
          seq_printf(m,"Current SRAM key memory chunk remaining --> %d\n\n\n",cavium_dev[i].fsk_chunk_count - cavium_dev[i].fsk_free_index);
         seq_printf(m,"Current DRAM key memory chunk allocated --> %d\n\n",cavium_dev[i].ex_keymem_free_index );
         seq_printf(m,"Current DRAM key memory chunk remaining --> %d\n\n\n",cavium_dev[i].ex_keymem_chunk_count - cavium_dev[i].ex_keymem_free_index
);
         seq_printf(m,"Current Host key memory chunk allocated --> %d\n\n",cavium_dev[i].host_keymem_free_index );
         seq_printf(m,"Current Host key memory chunk remaining --> %d\n\n",cavium_dev[i].host_keymem_count - cavium_dev[i].host_keymem_free_index );
      }
   }

   CAVIUM_MOD_DEC_USE_COUNT;

   return 0;
}


#ifdef COUNTER_ENABLE
static int cavium_proc_data_stat_show(struct seq_file *m, void *v)
{

   CAVIUM_MOD_INC_USE_COUNT;
    if (ssl != -1) {
      seq_printf(m,"------------------------------------------------------------------------\n");
      seq_printf(m,"                             SSL Record Processing\n");
      seq_printf(m,"------------------------------------------------------------------------\n");
      seq_printf(m,"                      Record Encrypt           Record Decrypt\n");
      seq_printf(m,"Packet Requests:%17d%24d\n",encrypt_record_count,decrypt_record_count);
      seq_printf(m,"Packet Aborts:  %17d%24d\n",enc_rec_pkt_err,dec_rec_pkt_err);
      seq_printf(m,"Bytes In:       %17lu%24lu\n",(unsigned long)bytes_in_rec_enc,(unsigned long)bytes_in_rec_dec);
      seq_printf(m,"Bytes Out:      %17lu%24lu\n",(unsigned long)bytes_out_rec_enc,(unsigned long)bytes_out_rec_dec);
   }
   if (ipsec != -1) {
      seq_printf(m,"------------------------------------------------------------------------\n");
      seq_printf(m,"\n                      IPSEC Inbound/Outbound Processing\n");
      seq_printf(m,"------------------------------------------------------------------------\n");
      seq_printf(m,"                        IPSec INBOUND           IPSec OUTBOUND\n");
      seq_printf(m,"Packet Requests:%17d%24d\n",ipsec_inbound_count,ipsec_outbound_count);
      seq_printf(m,"Packet Aborts:  %17d%24d\n",in_ipsec_pkt_err,out_ipsec_pkt_err);
      seq_printf(m,"Bytes In:       %17lu%24lu\n",(unsigned long)bytes_in_ipsec_ib,(unsigned long)bytes_in_ipsec_ob);
      seq_printf(m,"Bytes Out:      %17lu%24lu\n",(unsigned long)bytes_out_ipsec_ib,(unsigned long)bytes_out_ipsec_ob);
   }
      seq_printf(m,"------------------------------------------------------------------------\n");
      seq_printf(m,"\n                       Crypto Processing\n");
      seq_printf(m,"------------------------------------------------------------------------\n");
      seq_printf(m,"                           Encrypt                 Decrypt\n");
      seq_printf(m,"Packet Requests:%17d%24d\n",encrypt_count,decrypt_count);
      seq_printf(m,"Packet Aborts:  %17d%24d\n",enc_pkt_err,dec_pkt_err);
      seq_printf(m,"Bytes In:       %17lu%24lu\n",(unsigned long)bytes_in_enc,(unsigned long)bytes_in_dec);
      seq_printf(m,"Bytes Out:      %17lu%24lu\n",(unsigned long)bytes_out_enc,(unsigned long)bytes_out_dec);
      seq_printf(m,"------------------------------------------------------------------------\n");
      seq_printf(m,"                              HMAC\n");
      seq_printf(m,"Packet Requests:%17d\n",hmac_count);
      seq_printf(m,"Packet Aborts:  %17d\n",hmac_pkt_err);
      seq_printf(m,"Bytes In:       %17lu\n",(unsigned long)bytes_in_hmac);
      seq_printf(m,"Bytes Out:      %17lu\n",(unsigned long)bytes_out_hmac);
      seq_printf(m, "\n");
 
   CAVIUM_MOD_DEC_USE_COUNT;

   return 0;
}
#endif

static int cavium_proc_regs_show(struct seq_file *m, void *v)
{
   int i=0;
   Uint32 dwval = 0;
   cavium_device * ptr;

   CAVIUM_MOD_INC_USE_COUNT;

   seq_printf(m, "\n---Config ---\n\n");
   for (i = 0; i < dev_count; i++)
   {
      if(cavium_dev[i].enable)
      {
         ptr = &cavium_dev[i];
         seq_printf(m, "---------- \n");
         seq_printf(m, "DEVICE : %d \n",i);
         seq_printf(m, "---------- \n");
         read_PCI_register(ptr, 0x0, &dwval);
         seq_printf(m, "Config[0x000]: 0x%08x\n", dwval);
         read_PCI_register(ptr, 0x04, &dwval);
         seq_printf(m, "Config[0x004]: 0x%08x\n", dwval);
         read_PCI_register(ptr, 0x08, &dwval);
         seq_printf(m, "Config[0x008]: 0x%08x\n", dwval);
         read_PCI_register(ptr, 0x0C, &dwval);
         seq_printf(m, "Config[0x00c]: 0x%08x\n", dwval);
         read_PCI_register(ptr, 0x10, &dwval);
         seq_printf(m, "Config[0x010]: 0x%08x\n", dwval);
         read_PCI_register(ptr, 0x18, &dwval);
         seq_printf(m, "Config[0x018]: 0x%08x\n", dwval);
         read_PCI_register(ptr, 0x20, &dwval);
         seq_printf(m, "Config[0x020]: 0x%08x\n", dwval);
         read_PCI_register(ptr, 0x24, &dwval);
         seq_printf(m, "Config[0x024]: 0x%08x\n", dwval);
         read_PCI_register(ptr, 0x2C, &dwval);
         seq_printf(m, "Config[0x02C]: 0x%08x\n", dwval);
         read_PCI_register(ptr, 0x34, &dwval);
         seq_printf(m, "Config[0x034]: 0x%08x\n", dwval);
         read_PCI_register(ptr, 0x38, &dwval);
         seq_printf(m, "Config[0x038]: 0x%08x\n", dwval);
         read_PCI_register(ptr, 0x3C, &dwval);
         seq_printf(m, "Config[0x03C]: 0x%08x\n", dwval);
         read_PCI_register(ptr, 0x40, &dwval);
         seq_printf(m, "Config[0x040]: 0x%08x\n", dwval);
	if (!n3_vf_driver) {
         read_PCI_register(ptr, 0x44, &dwval);
         seq_printf(m, "Config[0x044]: 0x%08x\n", dwval);
         read_PCI_register(ptr, 0x50, &dwval);
         seq_printf(m, "Config[0x050]: 0x%08x\n", dwval);
         read_PCI_register(ptr, 0x54, &dwval);
         seq_printf(m, "Config[0x054]: 0x%08x\n", dwval);
	 } else {
         	read_PCI_register(ptr, 0x4C, &dwval);
         	seq_printf(m, "Config[0x4C]: 0x%08x\n", dwval);
	 }
         read_PCI_register(ptr, 0x58, &dwval);
         seq_printf(m, "Config[0x058]: 0x%08x\n", dwval);
	if (!n3_vf_driver) {
         read_PCI_register(ptr, 0x5C, &dwval);
         seq_printf(m, "Config[0x05C]: 0x%08x\n", dwval);

#if 0
         read_PCI_register(ptr, 0xE0, &dwval);
         seq_printf(m, "Config[0xE0]: 0x%08x\n", dwval);
         read_PCI_register(ptr, 0xE4, &dwval);
         seq_printf(m, "Config[0xE4]: 0x%08x\n", dwval);
         read_PCI_register(ptr, 0xE8, &dwval);
         seq_printf(m, "Config[0xE8]: 0x%08x\n", dwval);
#endif
         pci_read_config_dword(ptr->dev, 0x70, &dwval);
         seq_printf(m, "Config[0x070]: 0x%08x\n", dwval);
         pci_read_config_dword(ptr->dev, 0x74, &dwval);
         seq_printf(m, "Config[0x074]: 0x%08x\n", dwval);
	} //!n3_vf_driver
         pci_read_config_dword(ptr->dev, 0x78, &dwval);
         seq_printf(m, "Config[0x078]: 0x%08x\n", dwval);
	if (!n3_vf_driver) {
         pci_read_config_dword(ptr->dev, 0x7A, &dwval);
         seq_printf(m, "Config[0x07A]: 0x%08x\n", dwval);
         pci_read_config_dword(ptr->dev, 0x7C, &dwval);
         seq_printf(m, "Config[0x07A]: 0x%08x\n", dwval);
         pci_read_config_dword(ptr->dev, 0x80, &dwval);
         seq_printf(m, "Config[0x080]: 0x%08x\n", dwval);
	}
         pci_read_config_dword(ptr->dev, 0x110, &dwval);
         seq_printf(m, "Config[0x110]: 0x%08x\n", dwval);
         pci_read_config_dword(ptr->dev, 0x104, &dwval);
         seq_printf(m, "Config[0x104]: 0x%08x\n", dwval);

	if (n3_vf_driver) {
         pci_read_config_dword(ptr->dev, 0x80, &dwval);
         seq_printf(m, "Config[0x80]: 0x%08x\n", dwval);
         pci_read_config_dword(ptr->dev, 0x44, &dwval);
         seq_printf(m, "Config[0x44]: 0x%08x\n", dwval);
	}
      }
   }
   seq_printf(m, "\n---BAR0 ---\n\n");

   for (i = 0; i < dev_count; i++)
   {
      if(cavium_dev[i].enable)
      {
         ptr = &cavium_dev[i];
         /* BAR0 + 0 */
         seq_printf(m, "---------- \n");
         seq_printf(m, "DEVICE : %d \n",i);
         seq_printf(m, "---------- \n");
        if(cavium_dev[i].device_id == NPX_DEVICE){
         seq_printf(m, "\n---CSR ---\n\n");
         read_PKP_register(ptr, (ptr->CSRBASE_A + COMMAND_STATUS), &dwval);
         seq_printf(m, "Command Status Register    	    : 0x%x\n", dwval);
         /* BAR0 + 10h */
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_A + UNIT_ENABLE), &dwval);
         seq_printf(m, "Core Enable Register       	    : 0x%x\n", dwval);

         /* ssl and ipsec enabled regs */
		 if (ssl > 0)
            seq_printf(m, "SSL Enable Register     : 0x%06x\n", ssl_cores);
		 if (ipsec > 0)
            seq_printf(m, "IPSec Enable Register   : 0x%06x\n", ipsec_cores);

         /* BAR0 + 18h */
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_A + UCODE_LOAD), &dwval);
         seq_printf(m, "UCODE Load Register	   	    : 0x%x\n", dwval);
         /* BAR0 + 20h */
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_A + IMR_REG), &dwval);
         seq_printf(m, "Interrupt Enable Register  	    : 0x%x\n",dwval);
         /* BAR0 + 28h */
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_A + ISR_REG), &dwval);
         seq_printf(m, "Interrupt Status Register  	    : 0x%x\n",dwval);
         /* BAR0 + 30h */
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_A + FAILING_SEQ_REG), &dwval);
         seq_printf(m, "Core Error Address Register	    : 0x%x\n",dwval);
         /* BAR0 + 38h */
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_A + FAILING_EXEC_REG), &dwval);
         seq_printf(m, "Core Error Status Register 	    : 0x%x\n",dwval);                      /* BAR0 + 68h */
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_A + DEBUG_REG), &dwval);
         seq_printf(m, "Internal Status Register   	    : 0x%x\n",dwval);
         /* BAR0 + D0h */
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_A + PCI_ERR_REG), &dwval);
         seq_printf(m, "PCI Error Register	   	    : 0x%x\n",dwval);
#ifdef INTERRUPT_COALESCING
         /* BAR0 + 280h GENINT_COUNT_THOLD_REG*/
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_A + GENINT_COUNT_THOLD_REG), &dwval);
         seq_printf(m, "Interrupt Counter Threshold Register: 0x%x\n",dwval);
         /* BAR0 + 288h GENINT_COUNT_INT_TIME_REG*/
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_A + GENINT_COUNT_INT_TIME_REG), &dwval);
         seq_printf(m, "Interrupt Timer Threshold Register  : 0x%x\n",dwval);
         /* BAR0 + 290h GENINT_COUNT_REG*/
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_A + GENINT_COUNT_REG), &dwval);
         seq_printf(m, "Interrupt Counter Register	    : 0x%x\n",dwval);
         /* BAR0 + 298h GENINT_COUNT_TIMER*/
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_A + GENINT_COUNT_TIME_REG), &dwval);
         seq_printf(m, "Interrupt Timer Register	    : 0x%x\n",dwval);
#endif
	/*BAR0 +2A8h*/
         read_PKP_register(ptr, (ptr->CSRBASE_A + REG_EXEC_GROUP), &dwval);
         seq_printf(m, "Core Instruction Groups Register    : 0x%x\n",dwval);
	/*BAR0 +300*/
         read_PKP_register(ptr, (ptr->CSRBASE_A + EPC_EFUS_RCMD), &dwval);
         seq_printf(m, "FUSE Read Command Register	    : 0x%x\n",dwval);
	/*BAR0 +320*/
         read_PKP_register(ptr, (ptr->CSRBASE_A + EPC_EFUS_SPR_REPAIR_SUM), &dwval);
         seq_printf(m, "FUSE Repair Sum Register	    : 0x%x\n",dwval);
	/*BAR0 +328*/
         read_PKP_register(ptr, (ptr->CSRBASE_A + EPC_EFUS_SPR_REPAIR_RES0), &dwval);
         seq_printf(m, "FUSE Repair Result Register-0	    : 0x%x\n",dwval);
	/*BAR0 +330*/
         read_PKP_register(ptr, (ptr->CSRBASE_A + EPC_EFUS_SPR_REPAIR_RES1), &dwval);
         seq_printf(m, "FUSE Repair Result Register-1	    : 0x%x\n",dwval);
	/*BAR0 +338*/
         read_PKP_register(ptr, (ptr->CSRBASE_A + EPC_EFUS_SPR_REPAIR_RES2), &dwval);
         seq_printf(m, "FUSE Repair Result Register-2	    : 0x%x\n",dwval);
	/*BAR0 +348*/
         read_PKP_register(ptr, (ptr->CSRBASE_A + EPC_ADDR_INDEX), &dwval);
         seq_printf(m, "FUSE DMA Address Register	    : 0x%x\n",dwval);
	/*BAR0 +350*/
         read_PKP_register(ptr, (ptr->CSRBASE_A + EPC_EFUS_CORE_EN), &dwval);
         seq_printf(m, "FUSE Enabled Cores Register	    : 0x%x\n",dwval);
	/*BAR0 +358*/
         read_PKP_register(ptr, (ptr->CSRBASE_A + EPC_EFUS_CHIPID), &dwval);
         seq_printf(m, "FUSE Chip ID Register		    : 0x%x\n",dwval);
	/*BAR0 +400*/
         read_PKP_register(ptr, (ptr->CSRBASE_A + PCIE_CTL), &dwval);
         seq_printf(m, "PCIE Reset Register		    : 0x%x\n",dwval);
	/*BAR0 +408*/
         read_PKP_register(ptr, (ptr->CSRBASE_A + PCIE_INT_SUM), &dwval);
         seq_printf(m, "PCIE Interrupt Control Register	    : 0x%x\n",dwval);
	/*BAR0 +410*/
         read_PKP_register(ptr, (ptr->CSRBASE_A + PCIE_INT_ENB), &dwval);
         seq_printf(m, "PCIE Interrupt Enable Register	    : 0x%x\n",dwval);
	/*BAR0 +418*/
         read_PKP_register(ptr, (ptr->CSRBASE_A + PCIE_TO_STATUS), &dwval);
         seq_printf(m, "PCIE Timeout Status Register	    : 0x%x\n",dwval);
	/*BAR0 +420*/
         read_PKP_register(ptr, (ptr->CSRBASE_A + PCIE_CPL_ERR_STATUS1), &dwval);
         seq_printf(m, "PCIE Completion Error Status Reg1   : 0x%x\n",dwval);
	/*BAR0 +428*/
         read_PKP_register(ptr, (ptr->CSRBASE_A + PCIE_CPL_ERR_STATUS2), &dwval);
         seq_printf(m, "PCIE Completion Error Status Reg2   : 0x%x\n",dwval);
	/*BAR0 +430*/
         read_PKP_register(ptr, (ptr->CSRBASE_A + PCIE_CPL_ERR_STATUS3), &dwval);
         seq_printf(m, "PCIE Completion Error Status Reg3   : 0x%x\n",dwval);
	/*BAR0 +438*/
         read_PKP_register(ptr, (ptr->CSRBASE_A + PCIE_BIST_STATUS), &dwval);
         seq_printf(m, "PCIE BIST Status Register	    : 0x%x\n",dwval);
         /* BAR2 + 00h */
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_B + REQ0_BASE_HIGH), &dwval);
         seq_printf(m, "IQM 0 Base Address High Register    : 0x%x\n",dwval);
         /* BAR2 + 08h */
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_B + REQ0_BASE_LOW), &dwval);
         seq_printf(m, "IQM 0 Base Address Low Register     : 0x%x\n",dwval);
         /* BAR2 + 10h */
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_B + REQ0_SIZE), &dwval);
         seq_printf(m, "IQM 0 Queue Size Register	    : 0x%x\n",dwval);
         /* BAR2 + 18h */
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_B + REQ0_DOOR_BELL), &dwval);
         seq_printf(m, "IQM 0 Door Bell Register	    : 0x%x\n",dwval);
         /* BAR2 + 20h */
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_B + REQ1_BASE_HIGH), &dwval);
         seq_printf(m, "IQM 1 Base Address High Register    : 0x%x\n",dwval);
         /* BAR2 + 28h */
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_B + REQ1_BASE_LOW), &dwval);
         seq_printf(m, "IQM 1 Base Address Low Register     : 0x%x\n",dwval);
         /* BAR2 + 30h */
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_B + REQ1_SIZE), &dwval);
         seq_printf(m, "IQM 1 Queue Size Register	    : 0x%x\n",dwval);
         /* BAR2 + 38h */
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_B + REQ1_DOOR_BELL), &dwval);
         seq_printf(m, "IQM 1 Door Bell Register	    : 0x%x\n",dwval);
         /* BAR2 + 40h */
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_B + REQ2_BASE_HIGH), &dwval);
         seq_printf(m, "IQM 2 Base Address High Register    : 0x%x\n",dwval);
         /* BAR2 + 48h */
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_B + REQ2_BASE_LOW), &dwval);
         seq_printf(m, "IQM 2 Base Address Low Register     : 0x%x\n",dwval);
         /* BAR2 + 50h */
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_B + REQ2_SIZE), &dwval);
         seq_printf(m, "IQM 2 Queue Size Register	    : 0x%x\n",dwval);
         /* BAR2 + 58h */
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_B + REQ2_DOOR_BELL), &dwval);
         seq_printf(m, "IQM 2 Door Bell Register	    : 0x%x\n",dwval);
         /* BAR2 + 60h */
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_B + REQ3_BASE_HIGH), &dwval);
         seq_printf(m, "IQM 3 Base Address High Register    : 0x%x\n",dwval);
         /* BAR2 + 68h */
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_B + REQ3_BASE_LOW), &dwval);
         seq_printf(m, "IQM 3 Base Address Low Register     : 0x%x\n",dwval);
         /* BAR2 + 70h */
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_B + REQ3_SIZE), &dwval);
         seq_printf(m, "IQM 3 Queue Size Register	    : 0x%x\n",dwval);
         /* BAR2 + 78h */
         dwval = 0;
         read_PKP_register(ptr, (ptr->CSRBASE_B + REQ3_DOOR_BELL), &dwval);
         seq_printf(m, "IQM 3 Door Bell Register	    : 0x%x\n",dwval);
          if(ptr->device_id==NPX_DEVICE){
            /* BAR2 + 248h */
             dwval = 0;
             read_PKP_register(ptr, (ptr->CSRBASE_A + 0x200), &dwval);
             seq_printf(m, "IQM 0 next address high	    	    : 0x%x \n",dwval);
             read_PKP_register(ptr, (ptr->CSRBASE_A + 0x208), &dwval);
             seq_printf(m, "IQM 0 next address low              : 0x%x \n",dwval);
             read_PKP_register(ptr, (ptr->CSRBASE_A + 0x210), &dwval);
             seq_printf(m, "IQM 1 next address high 	    : 0x%x \n",dwval);
             read_PKP_register(ptr, (ptr->CSRBASE_A + 0x218), &dwval);
             seq_printf(m, "IQM 1 next address low  	    : 0x%x \n",dwval);
             read_PKP_register(ptr, (ptr->CSRBASE_A + 0x220), &dwval);
             seq_printf(m, "IQM 2 next address high 	    : 0x%x \n",dwval);
             read_PKP_register(ptr, (ptr->CSRBASE_A + 0x228), &dwval);
             seq_printf(m, "IQM 2 next address low    	    : 0x%x \n",dwval);
             read_PKP_register(ptr, (ptr->CSRBASE_A + 0x230), &dwval);
             seq_printf(m, "IQM 3 next address high 	    : 0x%x \n",dwval);
             read_PKP_register(ptr, (ptr->CSRBASE_A + 0x238), &dwval);
             seq_printf(m, "IQM 3 next address low  	    : 0x%x \n",dwval);
             read_PKP_register(ptr, (ptr->CSRBASE_A + 0x240), &dwval);
             seq_printf(m, "IQM 0 command count high	    : 0x%x \n",dwval);
             read_PKP_register(ptr, (ptr->CSRBASE_A + 0x248), &dwval);
             seq_printf(m, "IQM 0 command count low  	    : 0x%x \n",dwval);
             read_PKP_register(ptr, (ptr->CSRBASE_A + 0x250), &dwval);
             seq_printf(m, "IQM 1 command count high	    : 0x%x \n",dwval);
             read_PKP_register(ptr, (ptr->CSRBASE_A + 0x258), &dwval);
             seq_printf(m, "IQM 1 command count low 	    : 0x%x \n",dwval);
             read_PKP_register(ptr, (ptr->CSRBASE_A + 0x260), &dwval);
             seq_printf(m, "IQM 2 command count high	    : 0x%x \n",dwval);
             read_PKP_register(ptr, (ptr->CSRBASE_A + 0x268), &dwval);
             seq_printf(m, "IQM 2 command count low 	    : 0x%x \n",dwval);
             read_PKP_register(ptr, (ptr->CSRBASE_A + 0x270), &dwval);
             seq_printf(m, "IQM 3 command count high	    : 0x%x \n",dwval);
             read_PKP_register(ptr, (ptr->CSRBASE_A + 0x278), &dwval);
             seq_printf(m, "IQM 3 command count low 	    : 0x%x \n",dwval);
         }
       }else if(cavium_dev[i].device_id == N3_DEVICE){
	 Uint8 i,j;
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_COMPL_STATUS_SET), &dwval);
         seq_printf(m, "N3_COMPL_STATUS_SET	: 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_COMPL_STATUS_CLR), &dwval);
         seq_printf(m, "N3_COMPL_STATUS_CLR	: 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_GEN_ERR_STATUS_SET), &dwval);
         seq_printf(m, "N3_GEN_ERR_STATUS_SET	: 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_GEN_ERR_STATUS_CLR), &dwval);
         seq_printf(m, "N3_GEN_STATUS_CLR	: 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_COMP_ERR_STATUS_SET), &dwval);
         seq_printf(m, "N3_COMP_STATUS_SET	: 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_COMP_ERR_STATUS_CLR), &dwval);
         seq_printf(m, "N3_COMP_STATUS_CLR	: 0x%08x\n", dwval);
	 read_PKP_register(ptr, (ptr->CSRBASE_A  + N3_INT_PREVENT),&dwval);
	 seq_printf(m, "N3_INT_PREVENT		:0x%08x\n",dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_GEN_ERR_EN_SET), &dwval);
         seq_printf(m, "N3_GEN_ERR_EN_SET	: 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_GEN_ERR_EN_CLR), &dwval);
         seq_printf(m, "N3_GEN_ERR_EN_CLR	: 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_COMP_ERR_EN_SET), &dwval);
         seq_printf(m, "N3_COMP_ERR_EN_SET	: 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_COMP_ERR_EN_CLR), &dwval);
         seq_printf(m, "N3_COMP_ERR_EN_CLR	: 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_HSI_ERR_STAT_SET), &dwval);
         seq_printf(m, "N3_HSI_ERR_STAT_SET	: 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_HSI_ERR_STAT_CLR), &dwval);
         seq_printf(m, "N3_HSI_ERR_STAT_CLR	: 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_HSI_ERR_EN_SET), &dwval);
         seq_printf(m, "N3_HSI_ERR_EN_SET	: 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_HSI_ERR_EN_CLR), &dwval);
         seq_printf(m, "N3_HSI_ERR_EN_CLR	: 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CMD_REG), &dwval);
         seq_printf(m, "N3_CMD_REG         	: 0x%08x\n", dwval);
	 read_PKP_register(ptr,(ptr->CSRBASE_A + N3_ECC_ERR_ADDR), &dwval);
	 seq_printf(m, "N3_ECC_ERR_ADDR		: 0x%08x\n",dwval);
	 read_PKP_register(ptr,(ptr->CSRBASE_A + N3_ECC_ERR_SYN), &dwval);
	 seq_printf(m, "N3_ECC_ERR_SYN		: 0x%08x\n",dwval);
	 read_PKP_register(ptr,(ptr->CSRBASE_A + N3_CPL_ERR_INFO), &dwval);
	 seq_printf(m, "N3_CPL_ERR_INFO		: 0x%08x\n",dwval);
	 read_PKP_register(ptr,(ptr->CSRBASE_A + N3_CPL_TO_INFO), &dwval);
	 seq_printf(m, "N3_CPL_TO_INFO		: 0x%08x\n",dwval);
	 read_PKP_register(ptr,(ptr->CSRBASE_A + N3_ECC_CTRL), &dwval);
	 seq_printf(m, "N3_ECC_CTRL		: 0x%08x\n",dwval);
	 read_PKP_register(ptr,(ptr->CSRBASE_A + N3_SERDES_TUNING), &dwval);
	 seq_printf(m, "N3_SERDES_TUNING	: 0x%08x\n",dwval);
	for(i=0;i<=7;i++)
	{
	        read_PKP_register(ptr, (ptr->CSRBASE_A + (N3_PERF0_CTRL +(8*i))), &dwval);
	        seq_printf(m, "N3_IQM_PERF%d_CTRL      : 0x%08x\n",i, dwval);
	}
	for(i=0;i<=7;i++)
	{
	        read_PKP_register(ptr, (ptr->CSRBASE_A + (N3_PERF0_CNT +(8*i))), &dwval);
         	seq_printf(m, "N3_IQM_PERF%d_CNT       : 0x%08x\n",i, dwval);
	}
         seq_printf(m, "\n---IQM registers ---\n");
	for(i=0;i<=7;i++)
	{
         	read_PKP_register(ptr, (ptr->CSRBASE_A + (N3_IQM0_CNT_THOLD+ (0x40*i) )), &dwval);
         	seq_printf(m, "N3_IQM%d_CNT_THOLD      : 0x%08x\n",i, dwval);
	}
	for(i=0;i<=7;i++)
	{
         	read_PKP_register(ptr, (ptr->CSRBASE_A + (N3_IQM0_CMP_CNT+ (0x40*i) +8)), &dwval);
         	seq_printf(m, "N3_IQM%d_CMP_CNT        : 0x%08x\n",i, dwval);
	}
	for(i=0;i<=7;i++)
	{
         	read_PKP_register(ptr, (ptr->CSRBASE_A + (N3_IQM0_TIM_LD + (0x40*i) +0x10)), &dwval);
         	seq_printf(m, "N3_IQM%d_TIM_LD	       : 0x%08x\n",i, dwval);
	}
	for(i=0;i<=7;i++)
	{
         	read_PKP_register(ptr, (ptr->CSRBASE_A + (N3_IQM0_TIM+ (0x40*i) + 0x18)), &dwval);
         	seq_printf(m, "N3_IQM%d_TIM	       : 0x%08x\n",i, dwval);
	}
	for(i=0;i<=7;i++)
	{
         	read_PKP_register(ptr, (ptr->CSRBASE_A + (N3_IQM0_CNT_SUB+ (0x40*i) +0x20)), &dwval);
         	seq_printf(m, "N3_IQM%d_CNT_SUB	       : 0x%08x\n",i, dwval);
	}
	 for(i = 0;i < ptr->max_queues;i++)
	 {
		read_PKP_register(ptr,(ptr->CSRBASE_A+(N3_IQM0_DOOR_BELL_REG | (i<<8))),&dwval);
		seq_printf(m,"N3_IQMQ%d_DOOR_BELL_REG  : 0x%08x\n",i,dwval);
		read_PKP_register(ptr,(ptr->CSRBASE_A+(N3_IQM0_QSIZE | (i<<8))),&dwval);
		seq_printf(m,"N3_IQMQ%d_QSIZE          : 0x%08x\n",i,dwval);
		read_PKP_register(ptr,(ptr->CSRBASE_A+(N3_IQM0_BASE_ADDR_LO | (i<<8))),&dwval);
		seq_printf(m,"N3_IQMQ%d_BASE_ADDR_LO   : 0x%08x\n",i,dwval);
         	read_PKP_register(ptr, (ptr->CSRBASE_A + (N3_IQM0_BASE_ADDR_HI | (i<<8))), &dwval);
         	seq_printf(m, "N3_IQMQ%d_BASE_ADDR_HI  : 0x%08x\n",i, dwval);
         	read_PKP_register(ptr, (ptr->CSRBASE_A + (N3_IQM0_NXT_ADDR_LO | (i<<8))), &dwval);
         	seq_printf(m, "N3_IQMQ%d_NXT_ADDR_LO   : 0x%08x\n",i, dwval);
         	read_PKP_register(ptr, (ptr->CSRBASE_A + (N3_IQM0_NXT_ADDR_HI | (i<<8))), &dwval);
         	seq_printf(m, "N3_IQMQ%d_NXT_ADDR_HI   : 0x%08x\n", i,dwval);
         	read_PKP_register(ptr, (ptr->CSRBASE_A + (N3_IQM0_CMD_CNT_LO | (i<<8))), &dwval);
         	seq_printf(m, "N3_IQMQ%d_CMD_CNT_LO    : 0x%08x\n",i, dwval);
         	read_PKP_register(ptr, (ptr->CSRBASE_A + (N3_IQM0_CMD_CNT_HI | (i<<8))), &dwval);
         	seq_printf(m, "N3_IQMQ%d_CMD_CNT_HI    : 0x%08x\n",i, dwval);
         	read_PKP_register(ptr, (ptr->CSRBASE_A + (N3_IQM0_EXEC_MSK_LO | (i<<8))), &dwval);
         	seq_printf(m, "N3_IQMQ%d_EXEC_MSK_LO   : 0x%08x\n",i, dwval);
         	read_PKP_register(ptr, (ptr->CSRBASE_A + (N3_IQM0_EXEC_MSK_HI | (i<<8))), &dwval);
         	seq_printf(m, "N3_IQMQ%d_EXEC_MSK_HI   : 0x%08x\n",i, dwval);
         	read_PKP_register(ptr, (ptr->CSRBASE_A + (N3_IQM0_WDOG_CFG | (i<<8))), &dwval);
         	seq_printf(m, "N3_IQMQ%d_WDOG_CFG      : 0x%08x\n",i, dwval);
	}
	seq_printf(m, "\n---GROUP MASK registers---\n");
	for ( i=0;i<=7;i++)
	{
	        read_PKP_register(ptr, (ptr->CSRBASE_A + (N3_IQMQ_GRP0_EXECMSK_LO |(i<<8))), &dwval);
         	seq_printf(m, "N3_IQMQ_GRP%d_EXECMSK_LO : 0x%08x\n",i, dwval);
         	read_PKP_register(ptr, (ptr->CSRBASE_A +  (N3_IQMQ_GRP0_EXECMSK_HI |(i<<8))), &dwval);
         	seq_printf(m, "N3_IQMQ_GRP%d_EXECMSK_HI : 0x%08x\n",i, dwval);
	}
	seq_printf(m, "\n---CORE AVAIL registers---\n");
	for ( i=0;i<ptr->max_cores;i++)
	{
	        read_PKP_register(ptr, (ptr->CSRBASE_A + (N3_IQM_EXEC0_AVAIL |(i<<8))), &dwval);
      	 	seq_printf(m, "N3_IQM_EXEC%d_AVAIL      : 0x%08x\n",i, dwval);
	}
	seq_printf(m, "\n---IQM CONTROL/STATUS registers---\n"); 
	for(i=0;i<=7;i++)
	{
	        read_PKP_register(ptr, (ptr->CSRBASE_A + (N3_IQM_PERF_CTRL0 |(i<<12))), &dwval);
         	seq_printf(m, "N3_IQM_PERF_CTRL%d       : 0x%08x\n",i, dwval);
         	read_PKP_register(ptr, (ptr->CSRBASE_A +  (N3_IQM_PERF_CNT0 |(i<<12))), &dwval);
         	seq_printf(m, "N3_IQM_PERF_CNT%d        : 0x%08x\n",i, dwval);
	}
		
			
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_EN_LO), &dwval);
         seq_printf(m, "N3_IQM_EN_LO         : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_EN_HI), &dwval);
         seq_printf(m, "N3_IQM_EN_HI         : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_INT_STAT), &dwval);
         seq_printf(m, "N3_IQM_INT_STAT      : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_INT_STAT), &dwval);
         seq_printf(m, "N3_IQM_INT_STAT      : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_OVFL_LO), &dwval);
         seq_printf(m, "N3_IQM_OVFL_LO       : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_OVFL_HI), &dwval);
         seq_printf(m, "N3_IQM_OVFL_HI       : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_WDOG_LO), &dwval);
         seq_printf(m, "N3_IQM_WDOG_LO       : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_WDOG_HI), &dwval);
         seq_printf(m, "N3_IQM_WDOG_HI       : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_OVFL_EN_LO), &dwval);
         seq_printf(m, "N3_IQM_OVFL_EN_LO    : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_OVFL_EN_HI), &dwval);
         seq_printf(m, "N3_IQM_OVFL_EN_HI    : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_WDOG_EN_LO), &dwval);
         seq_printf(m, "N3_IQM_WDOG_EN_LO    : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_WDOG_EN_HI), &dwval);
         seq_printf(m, "N3_IQM_WDOG_EN_HI    : 0x%08x\n", dwval);
	 seq_printf(m, "\n---ERROR registers---\n");
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_SBE_COUNT), &dwval);
         seq_printf(m, "N3_IQM_SBE_COUNT     : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_SBE_LO), &dwval);
         seq_printf(m, "N3_IQM_SBE_LO        : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_SBE_HI), &dwval);
         seq_printf(m, "N3_IQM_SBE_HI        : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_SBE_EN_LO), &dwval);
         seq_printf(m, "N3_IQM_SBE_EN_LO     : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_SBE_EN_HI), &dwval);
         seq_printf(m, "N3_IQM_SBE_EN_HI     : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_DBE_LO), &dwval);
         seq_printf(m, "N3_IQM_DBE_LO        : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_DBE_HI), &dwval);
         seq_printf(m, "N3_IQM_DBE_HI        : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_DBE_EN_LO), &dwval);
         seq_printf(m, "N3_IQM_DBE_EN_LO     : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_DBE_EN_HI), &dwval);
         seq_printf(m, "N3_IQM_DBE_EN_HI     : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_RERR_LO), &dwval);
         seq_printf(m, "N3_IQM_RERR_LO       : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_RERR_HI), &dwval);
         seq_printf(m, "N3_IQM_RERR_HI       : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_RERR_EN_LO), &dwval);
         seq_printf(m, "N3_IQM_RERR_EN_LO    : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_RERR_EN_HI), &dwval);
         seq_printf(m, "N3_IQM_RERR_EN_HI    : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_EXEC_NA_LO), &dwval);
         seq_printf(m, "N3_IQM_EXEC_NA_LO    : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_EXEC_NA_HI), &dwval);
         seq_printf(m, "N3_IQM_EXEC_NA_HI    : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_EXEC_NA_EN_LO), &dwval);
         seq_printf(m, "N3_IQM_EXEC_NA_EN_LO : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_IQM_EXEC_NA_EN_HI), &dwval);
         seq_printf(m, "N3_IQM_EXEC_NA_EN_HI   : 0x%08x\n", dwval);
         seq_printf(m, "\n---CORE registers ---\n");
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_EN_0), &dwval);
         seq_printf(m, "N3_CORE_EN_0         : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_EN_1), &dwval);
         seq_printf(m, "N3_CORE_EN_1         : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_EN_2), &dwval);
         seq_printf(m, "N3_CORE_EN_2         : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_EN_3), &dwval);
         seq_printf(m, "N3_CORE_EN_3         : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_AVAIL_0), &dwval);
         seq_printf(m, "N3_CORE_AVAIL_0      : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_AVAIL_1), &dwval);
         seq_printf(m, "N3_CORE_AVAIL_1      : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_AVAIL_2), &dwval);
         seq_printf(m, "N3_CORE_AVAIL_2      : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_AVAIL_3), &dwval);
         seq_printf(m, "N3_CORE_AVAIL_3      : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_ISR_0), &dwval);
         seq_printf(m, "N3_CORE_ISR_0        : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_ISR_1), &dwval);
         seq_printf(m, "N3_CORE_ISR_1        : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_ISR_2), &dwval);
         seq_printf(m, "N3_CORE_ISR_2        : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_ISR_3), &dwval);
         seq_printf(m, "N3_CORE_ISR_3        : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_INT_EN_0), &dwval);
         seq_printf(m, "N3_CORE_INT_EN_0     : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_INT_EN_1), &dwval);
         seq_printf(m, "N3_CORE_INT_EN_1     : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_INT_EN_2), &dwval);
         seq_printf(m, "N3_CORE_INT_EN_2     : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_INT_EN_3), &dwval);
         seq_printf(m, "N3_CORE_INT_EN_3     : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_FINT_EN_0), &dwval);
         seq_printf(m, "N3_CORE_FINT_EN_0    : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_FINT_EN_1), &dwval);
         seq_printf(m, "N3_CORE_FINT_EN_1    : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_FINT_EN_2), &dwval);
         seq_printf(m, "N3_CORE_FINT_EN_2    : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_FINT_EN_3), &dwval);
         seq_printf(m, "N3_CORE_FINT_EN_3    : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_ADDR_SWAP_0), &dwval);
         seq_printf(m, "N3_CORE_ADDR_SWAP_0  : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_ADDR_SWAP_1), &dwval);
         seq_printf(m, "N3_CORE_ADDR_SWAP_1  : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_ADDR_SWAP_2), &dwval);
         seq_printf(m, "N3_CORE_ADDR_SWAP_2  : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_ADDR_SWAP_3), &dwval);
         seq_printf(m, "N3_CORE_ADDR_SWAP_3  : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_STATUS_0), &dwval);
         seq_printf(m, "N3_CORE_STATUS_0     : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_STATUS_1), &dwval);
         seq_printf(m, "N3_CORE_STATUS_1     : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_STATUS_2), &dwval);
         seq_printf(m, "N3_CORE_STATUS_2     : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_STATUS_3), &dwval);
         seq_printf(m, "N3_CORE_STATUS_3     : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_DBG_CTRL_0), &dwval);
         seq_printf(m, "N3_CORE_DBG_CTRL_0   : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_DBG_CTRL_1), &dwval);
         seq_printf(m, "N3_CORE_DBG_CTRL_1   : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_DBG_CTRL_2), &dwval);
         seq_printf(m, "N3_CORE_DBG_CTRL_2   : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_DBG_CTRL_3), &dwval);
         seq_printf(m, "N3_CORE_DBG_CTRL_3   : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_DBG_DATA_0), &dwval);
         seq_printf(m, "N3_CORE_DBG_DATA_0   : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_DBG_DATA_1), &dwval);
         seq_printf(m, "N3_CORE_DBG_DATA_1   : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_DBG_DATA_2), &dwval);
         seq_printf(m, "N3_CORE_DBG_DATA_2   : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_CORE_DBG_DATA_3), &dwval);
         seq_printf(m, "N3_CORE_DBG_DATA_3   : 0x%08x\n", dwval);
	 for(i=0;i<=7;i++)
	 {
		for(j=0;j<4;j++)
		{
         		read_PKP_register(ptr, (ptr->CSRBASE_A + (N3_CORE_PERF_CTRL0_0 + (j<<16)+ (8 * i) )), &dwval);
         		seq_printf(m, "N3_CORE_PERF_CTRL%d_%d   : 0x%08x\n",i,j ,dwval);
		}
         }
	 for(i=0;i<=7;i++)
	 {
		for(j=0;j<4;j++)
		{
         		read_PKP_register(ptr, (ptr->CSRBASE_A + (N3_CORE_PERF_CNT0_0 + (j<<16)+ (8 * i) )), &dwval);
         		seq_printf(m, "N3_CORE_PERF_CTRL%d_%d   : 0x%08x\n",i,j ,dwval);
		}
         }
	 for(i=0;i<=15;i++)
	 {
		for(j=0;j<4;j++)
		{
         		read_PKP_register(ptr, (ptr->CSRBASE_A + (N3_CORE0_INST_RPTR + (j<<16)+ ((8 * i)<<8) )), &dwval);
         		seq_printf(m, "N3_CORE%d_INST_RPTR_%d   : 0x%08x\n",i,j ,dwval);
		}
         }
	 for(i=0;i<=15;i++)
	 {
		for(j=0;j<4;j++)
		{
         		read_PKP_register(ptr, (ptr->CSRBASE_A + (N3_CORE0_CFG + (j<<16)+ ((8 * i)<<8) )), &dwval);
         		seq_printf(m, "N3_CORE%d_CFG_%d    	: 0x%08x\n",i,j ,dwval);
		}
         }
	 seq_printf(m,"\n---KEY MEMORY registers---\n");
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_KEY_INDIRECT_ADDRESS), &dwval);
         seq_printf(m, "N3_KEY_INDIRECT_ADDRESS : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_KEY_INDIRECT_DATA), &dwval);
         seq_printf(m, "N3_KEY_INDIRECT_DATA    : 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_KEY_INT_SUM), &dwval);
         seq_printf(m, "N3_KEY_INT_SUM   	: 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_KEY_INT_EN), &dwval);
         seq_printf(m, "N3_KEY_INT_EN   	: 0x%08x\n", dwval);
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_KEY_CTL_STATUS), &dwval);
         seq_printf(m, "N3_KEY_CTL_STATUS   	: 0x%08x\n", dwval);
	 seq_printf(m,"\n---RANDOM NUMBER GENERATOR registers---\n");
         read_PKP_register(ptr, (ptr->CSRBASE_A + N3_RNM_CTL_STATUS), &dwval);
         seq_printf(m, "N3_RNM_CTL_STATUS   	: 0x%08x\n", dwval);
	 
	 
       }
      }
   }

   CAVIUM_MOD_DEC_USE_COUNT;

   return 0;
}

static int cavium_proc_cmd_open(struct inode *inode, struct file *file)
{
        return single_open(file, cavium_proc_cmd_show, NULL);
}

static int cavium_proc_version_open(struct inode *inode, struct file *file)
{
        return single_open(file, cavium_proc_version_show, NULL);
}

#ifndef CTX_MEM_IS_HOST_MEM
static int cavium_proc_context_open(struct inode *inode, struct file *file)
{
        return single_open(file, cavium_proc_context_show, NULL);
}
#endif

//#ifdef SSL
static int cavium_proc_keymem_open(struct inode *inode, struct file *file)
{
        return single_open(file, cavium_proc_keymem_show, NULL);
}
//#endif


#ifdef COUNTER_ENABLE
static int cavium_proc_data_stat_open(struct inode *inode, struct file *file)
{
        return single_open(file, cavium_proc_data_stat_show, NULL);
}
#endif

static int cavium_proc_regs_open(struct inode *inode, struct file *file)
{
        return single_open(file, cavium_proc_regs_show, NULL);
}



static struct file_operations cavium_proc_cmd_operations = {
        .open = cavium_proc_cmd_open,
        .read = seq_read,
        .llseek = seq_lseek,
        .release = single_release,
};

static struct file_operations cavium_proc_version_operations = {
        .open = cavium_proc_version_open,
        .read = seq_read,
        .llseek = seq_lseek,
        .release = single_release,
};

#ifndef CTX_MEM_IS_HOST_MEM
static struct file_operations cavium_proc_context_operations = {
        .open = cavium_proc_context_open,
        .read = seq_read,
        .llseek = seq_lseek,
        .release = single_release,
};
#endif

//#ifdef SSL
static struct file_operations cavium_proc_keymem_operations = {
        .open = cavium_proc_keymem_open,
        .read = seq_read,
        .llseek = seq_lseek,
        .release = single_release,
};
//#endif


#ifdef COUNTER_ENABLE
static struct file_operations cavium_proc_data_stat_operations = {
        .open = cavium_proc_data_stat_open,
        .read = seq_read,
        .llseek = seq_lseek,
        .release = single_release,
};
#endif

static struct file_operations cavium_proc_regs_operations = {
        .open = cavium_proc_regs_open,
        .read = seq_read,
        .llseek = seq_lseek,
        .release = single_release,
};

struct proc_dir_entry * zip_proc_dir(void)
{
	return cavium_dir;
}
EXPORT_SYMBOL(zip_proc_dir);


int cavium_init_proc(void)
{
   int rv = 0;
   /* create directory /proc/cavium */
   cavium_dir = proc_mkdir("cavium", NULL);
   if(cavium_dir == NULL) {
      rv = -ENOMEM;
      goto out;
   }

#if LINUX_VERSION_CODE < KERNEL_VERSION (2,6,30)
   cavium_dir->owner = THIS_MODULE;
#endif

  /* create timeout file */
   timeout_file = create_proc_entry("command_timeout", 0644, cavium_dir);
   if(timeout_file == NULL)
   {
      rv = -ENOMEM;
      goto out;
   }
   timeout_file->data = &cavium_command_timeout;
   timeout_file->read_proc = proc_read_timeout;
   timeout_file->write_proc = proc_write_timeout;
#if LINUX_VERSION_CODE < KERNEL_VERSION (2,6,30)
   timeout_file->owner = THIS_MODULE;
#endif

   /* create debug_level */
   debug_level_file = create_proc_entry("debug_level", 0644, cavium_dir);
   if(debug_level_file == NULL)
   {
      rv = -ENOMEM;
      goto out;
   }
   debug_level_file->data = &cavium_debug_level;
   debug_level_file->read_proc = proc_read_debug_level;
   debug_level_file->write_proc = proc_write_debug_level;
#if LINUX_VERSION_CODE < KERNEL_VERSION (2,6,30)
   debug_level_file->owner = THIS_MODULE;
#endif

   /* create speed_timeout */
   speed_timeout_file = create_proc_entry("speed_timeout", 0644, cavium_dir);
   if(speed_timeout_file == NULL)
   {
      rv = -ENOMEM;
      goto out;
   }
   speed_timeout_file->data = &cavium_speed_timeout;
   speed_timeout_file->read_proc = proc_read_speed_timeout;
   speed_timeout_file->write_proc = proc_write_speed_timeout;
#if LINUX_VERSION_CODE < KERNEL_VERSION (2,6,30)
   speed_timeout_file->owner = THIS_MODULE;
#endif


   /* create data_stats_reset */
#ifdef COUNTER_ENABLE 
   data_stats_reset_file = create_proc_entry("data_stats_reset", 0644, cavium_dir);
   if(data_stats_reset_file == NULL)
   {
      rv = -ENOMEM;
      goto out;
   }
   data_stats_reset_file->data = &cavium_data_stats_reset;
   data_stats_reset_file->read_proc = proc_read_data_stats_reset;
   data_stats_reset_file->write_proc = proc_write_data_stats_reset;
#if LINUX_VERSION_CODE < KERNEL_VERSION (2,6,30)
   data_stats_reset_file->owner = THIS_MODULE;
#endif
#endif

   /* Create Command queue pointer location file */
   cmdquelocation_file = create_proc_entry("cmdquelocation", 0444,cavium_dir);
   if(cmdquelocation_file == NULL)
   {
      rv  = -ENOMEM;
      goto out;
   }
   cmdquelocation_file->proc_fops = &cavium_proc_cmd_operations;
#if LINUX_VERSION_CODE < KERNEL_VERSION (2,6,30)
   cmdquelocation_file->owner = THIS_MODULE;
#endif

   /* create version file*/
   version_file = create_proc_entry("version",0444,cavium_dir);
   if (version_file == NULL)
   {
      rv  = -ENOMEM;
      goto out;
   }
   version_file->proc_fops = &cavium_proc_version_operations;
#if LINUX_VERSION_CODE < KERNEL_VERSION (2,6,30)
   version_file->owner = THIS_MODULE;
#endif
 
#ifndef CTX_MEM_IS_HOST_MEM
   /* Creates Context Stats file */

   contextStats_file = create_proc_entry("contextStats",0444,cavium_dir);
   if (contextStats_file == NULL)
   {
      rv = -ENOMEM;
      goto out;
   }
   contextStats_file->proc_fops = &cavium_proc_context_operations;
#if LINUX_VERSION_CODE < KERNEL_VERSION (2,6,30)
   contextStats_file->owner = THIS_MODULE;
#endif
#endif

   /* Creates Key Memory Stats file */

   if (ssl>=0)
   {
      keymemStats_file = create_proc_entry("keymemStats",0444,cavium_dir);
      if (keymemStats_file == NULL)
      {
         rv = -ENOMEM;
         goto out;
      }
      keymemStats_file->proc_fops = &cavium_proc_keymem_operations;
#if LINUX_VERSION_CODE < KERNEL_VERSION (2,6,30)
      keymemStats_file->owner = THIS_MODULE;
#endif
   }

   /* create Data Stats file*/
#ifdef COUNTER_ENABLE
   data_stats_file = create_proc_entry("data_stats",0444,cavium_dir);
   if(data_stats_file == NULL)
   {
      rv  = -ENOMEM;
      goto out;
   }
   data_stats_file->proc_fops = &cavium_proc_data_stat_operations;
#if LINUX_VERSION_CODE < KERNEL_VERSION (2,6,30)
   data_stats_file->owner = THIS_MODULE;
#endif
#endif

   /* create Register file*/
   reg_file  = create_proc_entry("regs",0444,cavium_dir);
   if(reg_file == NULL)
   {
      rv  = -ENOMEM;
      goto out;
   }
   reg_file->proc_fops = &cavium_proc_regs_operations;
#if LINUX_VERSION_CODE < KERNEL_VERSION (2,6,30)
   reg_file->owner = THIS_MODULE;
#endif
   return 0;
out:
   if (reg_file)
   {
      remove_proc_entry("regs", cavium_dir);
   }
#ifdef COUNTER_ENABLE
   if (data_stats_file)
   {
      remove_proc_entry("data_stats", cavium_dir);
   }
#endif
   if (ssl>=0 && keymemStats_file)
   {
      remove_proc_entry("keymemStats", cavium_dir);
   }
#ifndef CTX_MEM_IS_HOST_MEM
   if(contextStats_file)
   {
       remove_proc_entry("contextStats_file", cavium_dir);
   }
#endif
   if(version_file)
   {
       remove_proc_entry("version_file", cavium_dir);
   }
   if (cmdquelocation_file)
   {
       remove_proc_entry("cmdquelocation", cavium_dir);
   }
#ifdef COUNTER_ENABLE
   if (data_stats_reset_file)
   {
      remove_proc_entry("data_stats_reset", cavium_dir);
   }
#endif
   if (debug_level_file)
   {
      remove_proc_entry("debug_level", cavium_dir);
   }
   if (speed_timeout_file)
   {
      remove_proc_entry("speed_timeout",cavium_dir);
   }
   if(timeout_file)
   {
      remove_proc_entry("command_timeout", cavium_dir);
   }
   if(cavium_dir)
   {
      remove_proc_entry("cavium", NULL);
   }
   return rv;
}

void  cavium_free_proc(void)
{
   if (reg_file)
   {
      cavium_print("Freeing regs\n");
      remove_proc_entry("regs", cavium_dir);
   }
#ifdef COUNTER_ENABLE
   if (data_stats_file)
   {
      cavium_print("Freeing data_stats\n");
      remove_proc_entry("data_stats", cavium_dir);
   }
#endif
//#ifdef SSL
   if (ssl>=0 && keymemStats_file)
   {
      cavium_print("Freeing KeymemStats\n");
      remove_proc_entry("keymemStats", cavium_dir);
   }
//#endif
#ifndef CTX_MEM_IS_HOST_MEM
   if(contextStats_file)
   {
      cavium_print("Freeing contextStats\n");
       remove_proc_entry("contextStats", cavium_dir);
   }
#endif
   if(version_file)
   {
      cavium_print("Freeing version\n");
       remove_proc_entry("version", cavium_dir);
   }
   if (cmdquelocation_file)
   {
      cavium_print("Freeing cmdquelocation\n");
       remove_proc_entry("cmdquelocation", cavium_dir);
   }
#ifdef COUNTER_ENABLE
   if (data_stats_reset_file)
   {
      cavium_print("Freeing data_stats_reset\n");
      remove_proc_entry("data_stats_reset", cavium_dir);
   }
 #endif
   if (debug_level_file)
   {
      cavium_print("Freeing debug_level\n");
      remove_proc_entry("debug_level", cavium_dir);
   }
   if (speed_timeout_file)
   {
      cavium_print("Freeing speed_timeout\n");
      remove_proc_entry("speed_timeout", cavium_dir);
   }
   if(timeout_file)
   {
      cavium_print("Freeing command_timeout\n");
      remove_proc_entry("command_timeout", cavium_dir);
   }
   if(cavium_dir)
   {
      cavium_print("Freeing cavium\n");
      remove_proc_entry("cavium", NULL);
   }
    return;
}




