/* linux_main.c */
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
/*------------------------------------------------------------------------------
 * 
 *      Linux Driver main file -- this file contains the driver code.
 *
 *----------------------------------------------------------------------------*/

#include <cavium_sysdep.h>
#include <cavium_common.h>
#include <cavium_ioctl.h>
#include <cavium_endian.h>
#include <linux/poll.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION (2,6,0)
#include <linux/wrapper.h>
#else
#include <linux/page-flags.h>
#endif
#include <linux/kdev_t.h>
#include <linux/pci.h>
#include "cavium_list.h"
#include "cavium.h"
#include "init_cfg.h"
#include "linux_main.h"
#include "cavium_proc.h"
#include "request_manager.h"
#include "context_memory.h"
#include "microcode.h"
#include "buffer_pool.h"
#include "hw_lib.h"
#include "key_memory.h"
#include "command_que.h"
#include<linux/stat.h>
#include<linux/smp.h>
#include<linux/workqueue.h>
#include<linux/cpu.h>
#include "interrupt.h"
MODULE_AUTHOR("Cavium Inc <www.cavium.com>");
MODULE_DESCRIPTION("Nitrox3/PX driver");
MODULE_LICENSE("GPL");
short ssl=-1, ipsec=-1, nplus=0, max_q=0;
short vf_count=0;
short maxcores=0;
int n3_vf_driver = 0;
module_param(ssl,short,S_IRUGO);
MODULE_PARM_DESC(ssl, "runs ssl on specified cores, if cores=0, uses all cores");
module_param(ipsec,short,S_IRUGO);
MODULE_PARM_DESC(ipsec, "runs ipsec on specified cores, if cores=0, uses all cores");
module_param(vf_count,short,S_IRUGO);
MODULE_PARM_DESC(vf_count, "no of vf functions");
module_param(maxcores,short,S_IRUGO);
MODULE_PARM_DESC(maxcores, "max no of cores");
short px_only = 0;
short n3_only = 0;
module_param(px_only,short,S_IRUGO);
MODULE_PARM_DESC(px_only, "enable px only devices");
module_param(n3_only,short,S_IRUGO);
MODULE_PARM_DESC(n3_only, "enable n3 only devices");
module_param(max_q,short,S_IRUGO);
MODULE_PARM_DESC(max_q, "max. no of queues");

/*
 * Device driver entry points
 */
extern Uint8 pf_vf[];
extern int reset_time;
int nr_cpus=0;
extern int boot_time;
extern int max_cpus;
struct workqueue_struct *work_queue[CPU_NUM];
struct delayed_work work[CPU_NUM];
int    initmodule (void);
static int __init cavium_driver_init(void);
static void __exit cavium_driver_exit(void);
void   cleanupmodule (void);
void   cleanup (struct pci_dev *dev);
int cavium_init_one(struct pci_dev *dev);
#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,11)
long    n1_unlocked_ioctl (struct file *, unsigned int, ptrlong);
#endif
int    n1_ioctl (struct inode *, struct file *, unsigned int, ptrlong);

long    n1_ioctl32 (struct file *, unsigned int, ptrlong);

#if LINUX_VERSION_CODE < KERNEL_VERSION (2,6,11)
int    n1_simulated_unlocked_ioctl (struct inode *, struct file *, unsigned int, ptrlong);
#endif
int    n1_open (struct inode *, struct file *);
int    n1_release (struct inode *, struct file *);
#ifndef CAVIUM_NO_MMAP
int   n1_mmap(struct file *, struct vm_area_struct *);
#endif
unsigned int n1_poll(struct file *, poll_table *);

struct N1_Dev *device_list = NULL;

extern cavium_device cavium_dev[];
extern int dev_count;
extern Uint8 cavium_version[3];
static int driver_removal = 0;
int next_dev=0;
int ssl_cores, ipsec_cores;
int init_flag = 0; //For core_migration
#ifdef CONFIG_PCI_MSI
int msi_enabled = 0;
#endif

#ifdef EXPORT_SYMTAB
EXPORT_SYMBOL(n1_ioctl);

EXPORT_SYMBOL(n1_ioctl32);

#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,11)
EXPORT_SYMBOL(n1_unlocked_ioctl);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION (2,6,11)
EXPORT_SYMBOL(n1_simulated_unlocked_ioctl);
#endif
EXPORT_SYMBOL(n1_open);
EXPORT_SYMBOL(n1_release);
#ifndef CAVIUM_NO_MMAP
EXPORT_SYMBOL(n1_mmap);
#endif
EXPORT_SYMBOL(n1_poll);
EXPORT_SYMBOL(init_buffer_pool);
EXPORT_SYMBOL(free_buffer_pool);
EXPORT_SYMBOL(get_buffer_from_pool);
EXPORT_SYMBOL(put_buffer_in_pool);
EXPORT_SYMBOL(pkp_setup_direct_operation);
EXPORT_SYMBOL(pkp_setup_sg_operation);
EXPORT_SYMBOL(check_endian_swap);
EXPORT_SYMBOL(pkp_unmap_user_buffers);
EXPORT_SYMBOL(pkp_flush_input_buffers);
EXPORT_SYMBOL(pkp_invalidate_output_buffers);
EXPORT_SYMBOL(check_completion);
EXPORT_SYMBOL(check_all_nb_command);
EXPORT_SYMBOL(reset_command_queue);
EXPORT_SYMBOL(inc_front_command_queue);
EXPORT_SYMBOL(cleanup_command_queue);
EXPORT_SYMBOL(init_command_queue);
EXPORT_SYMBOL(get_completion_dma);
EXPORT_SYMBOL(put_completion_dma);
#ifdef CAVIUM_RESOURCE_CHECK
EXPORT_SYMBOL(insert_ctx_entry);
#endif
EXPORT_SYMBOL(init_context); 
EXPORT_SYMBOL(cleanup_context);
EXPORT_SYMBOL(alloc_context);
EXPORT_SYMBOL(dealloc_context);
EXPORT_SYMBOL(set_PCIX_split_transactions);
EXPORT_SYMBOL(set_PCI_cache_line);
EXPORT_SYMBOL(set_soft_reset);
EXPORT_SYMBOL(do_soft_reset);
EXPORT_SYMBOL(count_set_bits);
EXPORT_SYMBOL(cavium_pow);
EXPORT_SYMBOL(get_exec_units_part);
EXPORT_SYMBOL(check_core_mask);
EXPORT_SYMBOL(get_first_available_core);
EXPORT_SYMBOL(get_unit_id);
#ifdef CAVIUM_RESOURCE_CHECK
EXPORT_SYMBOL(insert_key_entry);
#endif
EXPORT_SYMBOL(init_key_memory);
EXPORT_SYMBOL(cleanup_key_memory);
EXPORT_SYMBOL(store_key_mem);
EXPORT_SYMBOL(alloc_key_memory);
EXPORT_SYMBOL(dealloc_key_memory);
EXPORT_SYMBOL(flush_key_memory);
EXPORT_SYMBOL(send_command);
EXPORT_SYMBOL(do_operation);
EXPORT_SYMBOL(do_speed);
#endif

/*
 * Global variables
 */

static struct file_operations n1_fops =
{
     open		:n1_open,
     release		:n1_release,
     read		:NULL,
     write		:NULL,
#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,11)
     unlocked_ioctl	:n1_unlocked_ioctl,
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,11)
#if LINUX_VERSION_CODE < KERNEL_VERSION (2,6,36)
     ioctl		:n1_ioctl,
#endif
#else
     ioctl		:n1_simulated_unlocked_ioctl,
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION (2,4,20)
     /* no compact_ioct */
#else
     compat_ioctl	:n1_ioctl32,
#endif
#ifndef CAVIUM_NO_MMAP
     mmap		:n1_mmap,
#else
     mmap		:NULL,
#endif
     poll		:n1_poll,
};


struct __NITROX_DEVICES {
  Uint16   id;
  char     name[80];
};



#define MAX_NITROX_DEVLIST   2
#define __CVM_DRIVER_TYPE__  "Nitrox"
#define CVM_DRV_NAME        "pkp" 
struct __NITROX_DEVICES  nitrox_devices[MAX_NITROX_DEVLIST] =
{
 { NPX_DEVICE, "Nitrox-PX"},
 { N3_DEVICE,  "Nitrox3"}
};

int setup_interrupt(cavium_device *pdev);
void free_interrupt(cavium_device *pdev);
#if 0
/*
 * General
 */
#ifdef INTERRUPT_RETURN
extern int
#else
extern void
#endif
cavium_interrupt_handler_px(void *);
#endif
Uint32  csrbase_b_offset=0x0000;
static int __devinit cavium_probe(struct pci_dev *dev, const struct pci_device_id *ent)
{
  int ret_val=0, i;
  int device_id;  
  int cpu; 
  Uint16 dwval=0;
  static int count = 0;

#if defined(CAVIUM_DEBUG_LEVEL)
  cavium_debug_level = CAVIUM_DEBUG_LEVEL;
#else
  cavium_debug_level = 0;
#endif
  if (!dev) {
    ret_val = -1;
    goto error;
  }
  pci_read_config_word(dev, 0x34, &dwval);

  device_id= dev->device;      
  /* only PF will do init in PF driver case */
  if (device_id == N3_DEVICE && dwval == 0x70 && !count) {
      n3_vf_driver = 1;
      count++;
  } else if (dwval == 0x70 && count) {
      printk(KERN_CRIT "This is VF driver, doesn't require initialization\n");
      return -1;
  } else {
      count++;
  }



  if (px_only && (device_id != NPX_DEVICE)) {
     cavium_print("px only device set (ignoring non PX device) \n");
     goto error;
  }
  if (n3_only && (device_id != N3_DEVICE)) {
     cavium_print("n3 only device set (ignoring N3 device) \n");
     goto error;
  }
  /* Try to find a device listed in nitrox_devices */
  for(i = 0; i < MAX_NITROX_DEVLIST; i++) {

    if(device_id == nitrox_devices[i].id) {
#if CAVIUM_DEBUG_LEVEL>0
      printk("%s found at Bus %d Slot %d\n", nitrox_devices[i].name,
          dev->bus->number, PCI_SLOT(dev->devfn));
#endif

      break;
    }

  }
  if(i == MAX_NITROX_DEVLIST) {
    printk("CAVIUM Card found: But this driver is for %s\n",
        __CVM_DRIVER_TYPE__);
    ret_val = -1;
    goto error;
  }
  if (dev_count >= MAX_DEV) {
    cavium_print("MAX %d %s Devices supported\n", dev_count,
        __CVM_DRIVER_TYPE__);
    cavium_print("Ignoring other devices\n");
    goto error;
  }
  
  get_online_cpus();
  for_each_online_cpu(cpu){
    max_cpus++;
  }
  put_online_cpus();
  

  if (!cavium_init_one(dev)) {
    dev_count++;
    cavium_print("Finished Initializing this device\n");
  } else {
    cavium_error(" Cavium Init failed for device \n");
    ret_val = -ENOMEM;
    goto error;
  }
  if (dev_count == 0) {
    cavium_error("%s not found \n", __CVM_DRIVER_TYPE__);
    ret_val = -ENODEV;
    goto error;
  } else {
    cavium_print("Total Number of %s Devices: %d\n",
        __CVM_DRIVER_TYPE__, dev_count);
  }
error:
  return ret_val;
}
struct pci_device_id cavium_pci_table[] __devinitdata =
{
  {  VENDOR_ID,
    PCI_ANY_ID,    
    PCI_ANY_ID,            
    PCI_ANY_ID,            
    0, 0, 0    },
  {0},
};

struct pci_driver cavium_pci_driver = {
  .name     = "pkp",                     
  .probe    = cavium_probe,              
  .remove   = __devexit_p(cleanup),
  .id_table = cavium_pci_table,         
};
  int
cavium_init_one(struct pci_dev *dev)
{
  cavium_config cavium_cfg;
  unsigned long bar_px_hw=0;
  void  *bar_px = NULL;
  Uint32 NPX_BAR=0;   
  Uint32 bar_len=0;
  int ret_val=0;

  MPRINTFLOW();
  if(dev->device==NPX_DEVICE || dev->device == N3_DEVICE)
  {
    if(pci_find_capability(dev, PCI_CAP_ID_EXP))
    {       
      NPX_BAR= 0 ;
      if(dev->device != N3_DEVICE){
        cavium_cfg.px_flag=CN16XX;
      }else
        cavium_cfg.px_flag=0;
    }
    else
    {
      cavium_cfg.px_flag=CN15XX;
      NPX_BAR = 4;
    }   

  }else{
    cavium_cfg.px_flag=0;      
    NPX_BAR=0;
  }
  /* Enable PCI Device */
  if(pci_enable_device(dev))
  {
    cavium_error("pci_enable_device failed\n");
    return -1;
  }
  
  /* Enable PCI Bus Master */
  pci_set_master(dev);
 
  /* We should be able to access 64-bit mem space. */
  ret_val = pci_set_dma_mask(dev, 0xffffffffffffffffULL);
#if LINUX_VERSION_CODE  > KERNEL_VERSION (2,6,0)
  ret_val = pci_set_consistent_dma_mask(dev, 0xffffffffffffffffULL);
#endif

#if CAVIUM_DEBUG_LEVEL>0
    printk(KERN_CRIT "Using memory-mapped bar for device 0x%X:0x%X\n",
        VENDOR_ID, dev->device); 
#endif
    bar_px_hw = pci_resource_start(dev, NPX_BAR);
#if CAVIUM_DEBUG_LEVEL>0
    printk(KERN_CRIT "bar %d: %lx\n", NPX_BAR, bar_px_hw);
#endif
   
   bar_len=pci_resource_len(dev,NPX_BAR);
    /* get hold of memory-mapped region */
    bar_px = request_mem_region(bar_px_hw, bar_len, (const Uint8 *)CVM_DRV_NAME); 
    if(bar_px == NULL) {
      printk(KERN_CRIT " requested mem region for bar %d cannot be allocated\n", NPX_BAR);
      return -1;
    }

    bar_px = ioremap(bar_px_hw, bar_len);
    if(bar_px == NULL) {
      printk(KERN_CRIT "ioremap for bar %d memory failed\n", NPX_BAR);
      release_mem_region(bar_px_hw, bar_len);
      return -1;
    }
  if(dev->device==NPX_DEVICE){
    csrbase_b_offset = 0x0100;
  }

  cavium_cfg.dev= dev;
  cavium_cfg.bus_number = dev->bus->number; 
  cavium_cfg.dev_number = PCI_SLOT(dev->devfn);
  cavium_cfg.func_number = PCI_FUNC(dev->devfn);

  cavium_cfg.bar_px_hw = bar_px_hw;
  cavium_cfg.bar_px = bar_px;
  cavium_cfg.bar_len=bar_len;

  /* nr. of 32 byte contiguous structures */
  cavium_cfg.command_queue_max = CAVIUM_COMMAND_QUEUE_SIZE; 

  /* context memory to be pre-allocated,
   * if DDR memory is not found.
   * Otherwise actual size is used. */ 
  cavium_cfg.context_max = CAVIUM_CONTEXT_MAX; 
  cavium_cfg.device_id =dev->device;
  cavium_dev[dev_count].dev = dev;

  /* allocate command queue, initialize chip */
  if (cavium_init(&cavium_cfg)) {
      cavium_error("cavium_init failed.\n");
      if(bar_px)
        iounmap(bar_px);   
      release_mem_region(bar_px_hw, bar_len);
      return -ENOMEM;
  }

  return 0;
}

void cavium_cleanup_one(cavium_device *pkp_dev)
{
  cavium_cleanup(pkp_dev);

  if(pkp_dev->device_id==NPX_DEVICE || pkp_dev->device_id == N3_DEVICE){
    if(pkp_dev->bar_px)
      iounmap(pkp_dev->bar_px);
    if(pkp_dev->bar_px_hw)
      release_mem_region(pkp_dev->bar_px_hw, pkp_dev->bar_len);
  }
  return;
}
void cleanup(struct pci_dev *dev)
{
  int i;
  int device_id;
  Uint16 dwval;
  reset_time=1;
  device_id = dev->device;
  pci_read_config_word(dev, 0x34, &dwval);
 //VF also require cleanup
/*
  if(dwval == 0x70){
      printk(KERN_CRIT "VF doesn't require cleaup\n");
      return;
  }
*/
  for(i = 0; i < dev_count; i++) {
    if((cavium_dev[i].bus_number == dev->bus->number) &&
        (cavium_dev[i].device_id == device_id) &&
        (cavium_dev[i].dev_number == PCI_SLOT(dev->devfn)) &&
        (cavium_dev[i].func_number == PCI_FUNC(dev->devfn)))
    {
      break;
    }

  }
  if(device_id == N3_DEVICE && !n3_vf_driver && vf_count) {
	Uint32 dwval;
	cavium_device *pdev = &cavium_dev[i];
	read_PKP_register(pdev, (pdev->CSRBASE_A + N3_CMD_REG), &dwval);
	dwval &= (0 << 24);
	write_PKP_register(pdev, (pdev->CSRBASE_A + N3_CMD_REG), dwval);
      pci_disable_sriov(dev);
  }
  if(i<dev_count)
    cavium_cleanup_one(&cavium_dev[i]);
  pci_disable_device(dev);
}


/*
 *  Standard module initialization function.
 *  This function scans the PCI bus looking for the right board 
 *   and allocates resources.
 */

int initmodule ()
{
  int ret_val=0, i;
  if(cavium_general_init()) {
    cavium_error("cavium_general_init failed.\n");
    ret_val = -ENOMEM;
    goto init_error;
  }
  /* now setup interrupt handler */
  for (i = 0; i < dev_count; i++) {
    if(setup_interrupt(&cavium_dev[i])) {
      int j;
      ret_val = -ENXIO;
      for (j = 0; j <i; j++) {
        free_interrupt(&cavium_dev[j]);
      }
      cavium_print("Error setting up interrupt.\n");
      goto init_error;
    }
  }

  /* initialize kernel mode stuff */
  init_kernel_mode();

  /* register driver */
  ret_val = register_chrdev(DEVICE_MAJOR,DEVICE_NAME,&n1_fops);
  if(ret_val <0)
  {
    for (i = 0; i <dev_count; i++) {
      free_interrupt(&cavium_dev[i]);
    }
    printk("%s failed with %d\n", "Sorry, registering n1 device failed", ret_val);
    goto init_error;
  }

  if (cavium_init_proc()) {
    printk(" Support for proc filesystem failed\n");
    printk(" Still continuing ....\n");
  }

#if CAVIUM_DEBUG_LEVEL>0
  printk("Loaded Cavium Driver --- %01d.%02d-%c\n",cavium_version[0],cavium_version[1],cavium_version[2]);
#endif

  return 0;

init_error:
  cavium_general_cleanup();
  return ret_val;
}/*initmodule*/

/*
 *  Standard module release function.
 */
void cleanupmodule (void)
{
  int i;
#if LINUX_VERSION_CODE <= KERNEL_VERSION (2,6,22)
  int ret;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION (2,6,0)
  if(MOD_IN_USE) {    
    cavium_error("Nitrox device driver is in use\n"); 
    return;
  }
#endif
  driver_removal = 1;
  cavium_print("Unregistering char device\n");
#if LINUX_VERSION_CODE > KERNEL_VERSION (2,6,22)
  unregister_chrdev(DEVICE_MAJOR,DEVICE_NAME);
#else
  ret = unregister_chrdev(DEVICE_MAJOR,DEVICE_NAME);

  if(ret < 0) {
    cavium_error("Error in unregistering Nitrox device\n");
  } else {
    cavium_print("Nitrox Device successfully unregistered\n");
  }
#endif
  cavium_print("Freeing kernel mode\n");
  free_kernel_mode();

  cavium_print("Freeing interrupt\n");
  for (i=0; i < dev_count; i++)
    free_interrupt(&cavium_dev[i]);

  cavium_print("dev_count %d \n", dev_count);

}

/*
 *  Standard open() entry point.
 *  It simply increments the module usage count.
 */
int n1_open (struct inode *inode, struct file *file)
{
  Uint32 dev_id =0;
  struct MICROCODE *microcode = NULL;

  tracking_list *track_list;
  MPRINTFLOW();
  if(driver_removal) {
    cavium_print("open: returning error :%d\n", ENOMEM);
    return ENOMEM;
  }
  dev_id = MINOR(inode->i_rdev);
  CAVIUM_MOD_INC_USE_COUNT;
  if(dev_id!=PXDRV_LOAD_BALANCE_DEV){
    microcode = &(cavium_dev[dev_id].microcode[BOOT_IDX]);
    cavium_dbgprint("Microcode code_type = %d idx: %d,dev_id = %d\n",
    microcode->code_type, BOOT_IDX, dev_id); 

    cavium_dbgprint("n1_open(): Device minor number %d.%d\n", 
      inode->i_rdev >>8, inode->i_rdev & 0xff);
    microcode->use_count++;
    cavium_dbgprint("Microcode[%d] use_count: %d\n",
      BOOT_IDX, microcode->use_count);
  } 
  track_list = cavium_malloc(sizeof(tracking_list), NULL);
  if (track_list == NULL) {
    cavium_error("Unable to allocate memory for per process list\n");
    return -ERESTARTSYS;
  }
  cavium_spin_lock_init(&track_list->resource_lock);
  cavium_spin_lock_init(&track_list->nbl_lock);
  CAVIUM_INIT_LIST_HEAD(&track_list->ctx_head);
  CAVIUM_INIT_LIST_HEAD(&track_list->key_head);
  CAVIUM_INIT_LIST_HEAD(&track_list->nbl);
  track_list->pid=current->pid;
  track_list->next=1;
  track_list->pending=0;
  file->private_data = track_list;
  return (0);
}


/*
 *  Standard release() entry point.
 *  This function is called by the close() system call.
 */
int n1_release (struct inode *inode, struct file *file)
{

  int ret=driver_removal;
  struct MICROCODE *microcode = NULL;
  MPRINTFLOW();
  if(ret)
  {
    cavium_print("n1: close returning error %d\n", ENXIO);
    return ENXIO;
  }
  else
  {
    Uint32 dev_id=0;
    tracking_list *track_list = NULL;
#ifdef CAVIUM_RESOURCE_CHECK
    struct cavium_list_head *tmp, *tmp1;
#endif
    dev_id = MINOR(inode->i_rdev);
    if (dev_id > (dev_count - 1)&& dev_id!=PXDRV_LOAD_BALANCE_DEV) {
      cavium_print("\n no No N1 device associated with this minor device no. %d\n", dev_id);
      return -ENODEV;
    }
    track_list = file->private_data;
    if (track_list == NULL) {
      cavium_error("Resource not found while deallocating\n");
      return -1;
    }
#ifdef CAVIUM_RESOURCE_CHECK
    cavium_list_for_each_safe(tmp, tmp1, &track_list->ctx_head) {
     struct CTX_ENTRY *entry = list_entry(tmp, struct CTX_ENTRY, list);
      dealloc_context(entry->pkp_dev, entry->ctx_type, entry->ctx);
      cavium_list_del(&entry->list);
      cavium_free((Uint8 *)entry);
    }

    cavium_list_for_each_safe(tmp, tmp1, &track_list->key_head) {
      struct KEY_ENTRY *entry = list_entry(tmp, struct KEY_ENTRY, list);
      dealloc_key_memory(entry->pkp_dev, entry->key_handle);
      cavium_list_del(&entry->list);
      cavium_free((Uint8 *)entry);
    }
#endif
    cavium_free(track_list);
    CAVIUM_MOD_DEC_USE_COUNT;
    cavium_dbgprint("n1: close pid %d \n",cavium_get_pid());
    if(dev_id!=PXDRV_LOAD_BALANCE_DEV)
    {
      Uint32 dev_id=0;    
      dev_id = MINOR(inode->i_rdev);
      microcode = &(cavium_dev[dev_id].microcode[BOOT_IDX]);
      microcode->use_count--;
      cavium_dbgprint("Microcode[%d] use_count: %d\n",BOOT_IDX, microcode->use_count);
    }
    return(0);
  }
}


int acquire_core(cavium_device *pdev, int ucode_idx, int core_id)
{
  Cmd strcmd;
  int ret = 0, insize = 8, outsize = 16;
  Uint8 *out_buffer=NULL;
  Uint8 *in_buffer=NULL;
  Request request;
  Uint64 *completion_address;
  Uint64 disabled_core;
  Uint64 disabled_mask = 0;
  Uint64 dataptr = 0;
  Uint64 recvptr = 0;

  cavium_dbgprint("Attempt to acquire core %d\n", core_id);
  MPRINTFLOW();


  in_buffer = (Uint8 *)get_buffer_from_pool(pdev, (insize + 8));
  if(in_buffer == NULL)
  {
    cavium_print("acquire_core: unable to allocate in_buffer.\n");
    ret = -1;
    goto ca_err;
  }

  out_buffer = (Uint8 *)get_buffer_from_pool(pdev, (outsize + 8));
  if(out_buffer == NULL)
  {
    cavium_print("acquire_core: unable to allocate out_buffer.\n");
    ret = -2;
    goto ca_err;
  }

  dataptr = (Uint64)cavium_map_kernel_buffer(pdev,
      in_buffer, insize+8, CAVIUM_PCI_DMA_BIDIRECTIONAL);
  recvptr = (Uint64)cavium_map_kernel_buffer(pdev,
      out_buffer, outsize+8, CAVIUM_PCI_DMA_BIDIRECTIONAL);

  do
  {
    strcmd.opcode= (0x7f<<8) | MAJOR_OP_ACQUIRE_CORE;;
    strcmd.size  = 0;
    strcmd.param = 0;
    strcmd.dlen  = insize>>3;

    strcmd.opcode  = htobe16(strcmd.opcode);
    strcmd.size    = htobe16(strcmd.size);
    strcmd.param   = htobe16(strcmd.param);
    strcmd.dlen    = htobe16(strcmd.dlen);

    cavium_memcpy((unsigned char *)&request, (unsigned char *)&strcmd, 8);

    request.cptr = 0;

    request.dptr = htobe64(dataptr);
    request.rptr = htobe64(recvptr);
    request.cptr = htobe64(request.cptr);

    completion_address = (Uint64 *)(out_buffer + outsize);
    *completion_address = COMPLETION_CODE_INIT;

    if(send_command(pdev, &request, 0, ucode_idx, completion_address) < 0) {
      cavium_print("Error sending core acquire request.\n");
      goto ca_err;
    }

    ret = check_completion(pdev, completion_address, 100, ucode_idx, -1);
    if(ret) {
      cavium_print("Error: %x on acquire core request.\n", ret);
      goto ca_err;
    }
    disabled_core = betoh64(*(Uint64 *)(out_buffer+8));

    cavium_dbgprint("Acquired core %d\n", (Uint32)(disabled_core));

    if(disabled_core == core_id)
    {
      break;
    }
    else
    {
      disabled_mask |= (((Uint64)1)<<disabled_core);
      cavium_dbgprint("Acquired mask 0x%llx\n", disabled_mask);
    }
  } while(1);

ca_err:
  if(disabled_mask)
  {
    pdev->cavfns.disable_exec_units_from_mask(pdev, disabled_mask);
    pdev->cavfns.enable_exec_units_from_mask(pdev, disabled_mask);
    cavium_dbgprint("Cycled cores 0x%llx\n", disabled_mask);
  }

  if(in_buffer)
  {
    /*unmap the dma buffers*/
    cavium_unmap_kernel_buffer(pdev, dataptr, insize+8,
        CAVIUM_PCI_DMA_BIDIRECTIONAL);
    put_buffer_in_pool((Uint8 *)in_buffer,(insize+8));
  }
  if(out_buffer)
  {
    /*unmap the dma buffers*/
    cavium_unmap_kernel_buffer(pdev, recvptr, outsize+8,
        CAVIUM_PCI_DMA_BIDIRECTIONAL);
    put_buffer_in_pool((Uint8 *)out_buffer,(outsize+8));
  }
  return(ret);

}

  int 
nplus_init(cavium_device *pdev, int ucode_idx, unsigned long arg)
{
  int i, ret=0;
  int offset=40;
  Uint8 code_idx;
  Csp1InitBuffer *init_buffer;
  struct MICROCODE *microcode;

  init_buffer = (Csp1InitBuffer *)arg;

  MPRINTFLOW();
  cavium_dbgprint("got csp1_init code\n");
  cavium_dbgprint("size = %d\n", init_buffer->size);

  /* We only allow this IOCTL on "/dev/pkp_admin" */

  if(ucode_idx != BOOT_IDX )
  {
    cavium_print("Inappropriate IOCTL for device %d",ucode_idx);
    ret = ERR_INIT_FAILURE;
    goto cleanup_init;
  }

  /* Was this driver initialized earlier ? */
  if(pdev->initialized)
  {
    if(pdev->initialized == 1)
      cavium_error("Device already initialized\n");
    else
      cavium_error("Device incorrectly initialized\n");

    cavium_print("To reinitialize device, please unload & reload driver\n");
    ret = ERR_INIT_FAILURE;
    goto cleanup_init;
  }

  /* get all the information from init buffer */
  for(i=0;i<init_buffer->size;i++)
  {
    code_idx = init_buffer->ucode_idx[i];
    microcode = &(pdev->microcode[code_idx]);

    /* Make sure it isnt previously initialized */
    if(microcode->code != NULL)
    {
      cavium_print("Code Index %d found more than once\n", code_idx);
      ret = ERR_INIT_FAILURE;
      goto cleanup_init;
    }

    /* code */
    microcode->code_type = init_buffer->version_info[i][0] & 0x7f;

    /*** Paired cores is not supported in NitroxPX */
    if(pdev->device_id!=NPX_DEVICE)
      microcode->paired_cores
        = (init_buffer->version_info[i][0] & 0x80 ? 1:0);
    microcode->code_size = init_buffer->code_length[i];
    microcode->code = 
      (Uint8 *)get_buffer_from_pool(pdev,microcode->code_size);

    if (microcode->code == NULL)
    {
      cavium_print("Failed to allocate %d bytes microcode buffer type %d\n", 
          microcode->code_size, microcode->code_type);
      ret = ERR_MEMORY_ALLOC_FAILURE;
      goto cleanup_init;
    }            

    if(cavium_copy_in(microcode->code, CAST_FRM_X_PTR(init_buffer->code[i]),
          microcode->code_size))
    {
      cavium_error("Failed to copy in microcode->code\n");
      ret = ERR_INIT_FAILURE;
      goto cleanup_init;
    }

    /* data */
    microcode->data_size = init_buffer->data_length[i];
    if(microcode->data_size)
    {

      microcode->data =  (Uint8 *)cavium_malloc_nc_dma(pdev,
          microcode->data_size+offset,
          &microcode->data_dma_addr);

      if (microcode->data == NULL)
      {
        cavium_print("Failed to allocate %d bytes admin cst buffer type %d\n",
            microcode->data_size+offset,microcode->code_type);
        ret = ERR_MEMORY_ALLOC_FAILURE;
        goto cleanup_init;
      } 

      cavium_memset(microcode->data,0,microcode->data_size+offset);
      if(cavium_copy_in(microcode->data+offset, 
            CAST_FRM_X_PTR(init_buffer->data[i]),
            microcode->data_size))
      {
        cavium_error("Failed to copy in microcode->data\n");
        ret = ERR_INIT_FAILURE;
        goto cleanup_init;
      }
    }

    /* sram address */
    if(cavium_copy_in(microcode->sram_address,
          init_buffer->sram_address[i], SRAM_ADDRESS_LEN))
    {
      cavium_error("Failed to copy in sram_address\n");
      ret = ERR_INIT_FAILURE;
      goto cleanup_init;
    }
    if(pdev->device_id != NPX_DEVICE)
    {
      int j;
      /* Initialize the SRQ */
      microcode->srq.head = microcode->srq.tail = 0;
      microcode->srq.qsize = 0;
      cavium_spin_lock_init(&microcode->srq.lock);
      for(j=0;j<MAX_SRQ_SIZE;j++)
      {
        microcode->srq.state[j] = SR_FREE;
      }
    }
    cavium_dbgprint("Code type = %02x, code size = %x, data size = %x\n",
        microcode->code_type, microcode->code_size,microcode->data_size);
  }

  /* check for any missing piece */
  if(pdev->microcode[BOOT_IDX].code == NULL)
  {
    cavium_print("Boot code not sent to driver.\n");
    cavium_print("Please check version information\n");
    ret = ERR_INIT_FAILURE;
    goto cleanup_init;
  }

  /* We have gathered all the required information from init_buffer
   * Now it is time for some action. Lets do it! 
   */
  cavium_dbgprint("nplus_init: calling do_init\n");
  ret = do_init(pdev);   

cleanup_init:
  if(ret != 0)
  {

    for(i=0;i<init_buffer->size;i++)
    {
      code_idx = init_buffer->ucode_idx[i];
      microcode = &(pdev->microcode[code_idx]);
      if(microcode->code)
      {
        put_buffer_in_pool(microcode->code,microcode->code_size);
        microcode->code = NULL;
      }
      if(microcode->data)
      {
        cavium_free_nc_dma(pdev,
            microcode->data_size+offset,
            microcode->data,
            microcode->data_dma_addr);
        microcode->data_size = 0;
        microcode->data_dma_addr = 0;
        microcode->data = NULL;
      }
    }
    pdev->initialized = -1;
  }
  else
    pdev->initialized = 1;

  return ret;
}/*nplus_init*/

#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,11)
/* High performance ioctl */
long    n1_unlocked_ioctl (struct file *file, unsigned int cmd, ptrlong arg)
{
  cavium_dbgprint("inside n1_unlocked_ioctl\n");
  return (long)n1_ioctl(file->f_dentry->d_inode,file,cmd,arg);   
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)
int n1_simulated_unlocked_ioctl(struct inode *inode, struct file*file,unsigned int cmd,unsigned long arg)
{
  int ret;
#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,2)
  unlock_kernel();
#endif
  ret = n1_ioctl(inode,file,cmd,arg);
#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,2)
  lock_kernel();
#endif
  return ret;
}
#endif

long n1_ioctl32 (struct file *file,
    unsigned int cmd,unsigned long arg)
{
  struct inode  *inode = file->f_dentry->d_inode;
  MPRINTFLOW();
  return (long) n1_ioctl(inode, file, cmd, arg);

}
/*
 *  Standard ioctl() entry point.
 */
int n1_ioctl (struct inode *inode, struct file *file, 
    unsigned int cmd,unsigned long arg)
{
  int ret=0;
  Uint32  data32;

  Uint32 rval=0;

  DebugRWReg *dw;
  cavium_device *pdev=NULL;
  Uint32 dev_id=0;
  Csp1InitBuffer *init_buffer;
  tracking_list *track_list=file->private_data;
  dev_id = MINOR(inode->i_rdev);
  if(dev_id ==PXDRV_LOAD_BALANCE_DEV)
  {

      dev_id=next_dev;
      next_dev=(next_dev+1)%dev_count;
       
  }
  if (dev_id > (dev_count - 1)) {
    cavium_print("No N1 device associated with this minor device no. %d\n", dev_id);
    return -ENODEV;
  }

  MPRINTFLOW();
  pdev = &cavium_dev[dev_id];
  cavium_dbgprint("\n Cmd: %x, device id = %d, init = %d\n",cmd,dev_id,pdev->enable);

  switch (cmd) {
    /* write PKP register */
    case IOCTL_N1_DEBUG_WRITE_CODE:
      dw =  (DebugRWReg *)arg;
      data32 = dw->data & 0xffffffff;

      if(pdev->device_id==NPX_DEVICE)
        read_PKP_register(pdev, (Uint8 *)CAST_FRM_X_PTR(dw->addr), &rval);

      cavium_dbgprint("pkp_drv: writing 0x%x at 0x%llx\n", 
          data32, CAST64(dw->addr));
      write_PKP_register(pdev, (Uint8 *)CAST_FRM_X_PTR(dw->addr), data32);

      if(pdev->device_id==NPX_DEVICE){   
        if(( (Uint8 *)CAST_FRM_X_PTR(dw->addr) == pdev->CSRBASE_A + UNIT_ENABLE) && !(rval & 0x10000000) && (data32 & 0x10000000))
        {
          int i;
          for(i=0; i<MAX_N1_QUEUES; i++)
            reset_command_queue(pdev, i);
        }
      }

      ret = 0;
      break;

      /* Read PKP register */
    case IOCTL_N1_DEBUG_READ_CODE:
      dw = (DebugRWReg *)arg;
      cavium_dbgprint( "Kernel: reading 0x%llx \n", CAST64(dw->addr));
      read_PKP_register(pdev, (Uint8 *)CAST_FRM_X_PTR(dw->addr), &dw->data);
      cavium_dbgprint("Kernel read 0x%llx from 0x%llx\n",
          CAST64(dw->data), CAST64(dw->addr));
      ret = 0;
      break;

      /* Write PCI config space */
    case IOCTL_PCI_DEBUG_WRITE_CODE:
      dw =  (DebugRWReg *)arg;
      data32 = dw->data & 0xffffffff;
      cavium_dbgprint("pkp_drv: writing 0x%x at PCI config 0x%llx\n", 
          data32, CAST64(dw->addr));
      pci_write_config_dword((struct pci_dev *)(pdev->dev), dw->addr,
          data32);
      ret = 0;
      break;

      /* Read PCI config space */
    case IOCTL_PCI_DEBUG_READ_CODE:
      dw = (DebugRWReg *)arg;
      dw->data = 0;
      cavium_dbgprint("pkp_drv: reading PCI config 0x%llx\n",
          CAST64(dw->addr));
      pci_read_config_dword((struct pci_dev *)(pdev->dev), dw->addr,
          (u32 *)&data32);
      dw->data = (Uint64)data32;

      if(pdev->device_id==NPX_DEVICE){
        if(dw->addr == 0x10)
          dw->data = (Uint64)CAST_TO_X_PTR(pdev->bar_px) + BASE_A_OFFSET;
        if(dw->addr == 0x18)
          dw->data = (Uint64)CAST_TO_X_PTR(pdev->bar_px) + BASE_B_OFFSET;
      }else if(pdev->device_id==N3_DEVICE)
          dw->data = (Uint64)CAST_TO_X_PTR(pdev->bar_px) + BASE_A_OFFSET;
cavium_dbgprint("pkp_drv:dword at PCI config 0x:%llx is 0x:%llx\n",CAST64(dw->addr),dw->data);
      ret = 0;
      break;

      /* run some basic test */
    case IOCTL_N1_API_TEST_CODE:
      ret = -11;
      break;

    case IOCTL_N1_DO_OPERATION:
      {
        n1_operation_buffer *buf;
        buf = (n1_operation_buffer *)arg;
        cavium_dbgprint("ioctl N1 do operation called with opcode 0x%x\n", 
            buf->opcode);
        if(buf->dma_mode==CAVIUM_SCATTER_GATHER) {
              buf->opcode = buf->opcode & (~0x80);
        }
        if (buf->group==CAVIUM_IPSEC_GRP && (!nplus && ipsec == -1))
        {
          cavium_dbgprint("Driver not running for IPSec\n");
          return ERR_OPERATION_NOT_SUPPORTED;
        }
        if (buf->group==CAVIUM_SSL_GRP && (!nplus && ssl == -1))
        {
          cavium_dbgprint("Driver not running for SSL\n");
          return ERR_OPERATION_NOT_SUPPORTED;
        }
        if (buf->group != CAVIUM_GP_GRP && buf->group != CAVIUM_SSL_GRP && 
            buf->group != CAVIUM_IPSEC_GRP )
        {
          cavium_error ("Unknown Group operation\n");
          return ERR_OPERATION_NOT_SUPPORTED;
        }

        buf->ucode_idx = (buf->group==CAVIUM_IPSEC_GRP)?UCODE_IDX+nplus:UCODE_IDX;
        cavium_dbgprint("IOCTL_DO_OP:ucodeidx=%d, group: %d, nplus: %d\n", buf->ucode_idx, buf->group, nplus);
        if(buf->req_type == CAVIUM_SPEED) 
          ret = do_speed(pdev, buf);
        else
          ret = do_operation(pdev, buf,(void *)track_list);
        if(ret == ERR_REQ_PENDING)
        {
          buf->status= EAGAIN;
          ret= 0;
        }
      }
      cavium_dbgprint("ioctl N1 do operation returning.\n");
      break;
    case IOCTL_N1_DO_SG_OPERATION:
      {
        n1_operation_buffer *buf;

        buf = (n1_operation_buffer *)arg;
        cavium_dbgprint("ioctl N1 do operation called with opcode 0x%x\n", 
            buf->opcode);
        if (buf->group==CAVIUM_IPSEC_GRP && (!nplus || ipsec == -1))
        {
          cavium_dbgprint("Driver not running for IPSec\n");
          return ERR_OPERATION_NOT_SUPPORTED;
        }
        if (buf->group==CAVIUM_SSL_GRP && (!nplus || ssl == -1))
        {
          cavium_dbgprint("Driver not running for SSL\n");
          return ERR_OPERATION_NOT_SUPPORTED;
        }
        if (buf->group != CAVIUM_GP_GRP && buf->group != CAVIUM_SSL_GRP && 
            buf->group != CAVIUM_IPSEC_GRP )
        {
          cavium_error ("Unknown Group operation\n");
          return ERR_OPERATION_NOT_SUPPORTED;
        }
        buf->dma_mode = CAVIUM_SCATTER_GATHER;
        buf->ucode_idx = (buf->group==CAVIUM_IPSEC_GRP)?UCODE_IDX+nplus:UCODE_IDX;
        buf->opcode = buf->opcode & (~0x80);
        ret = do_operation(pdev, buf,(void *)track_list);
      }
      break;
    case IOCTL_N1_GET_REQUEST_STATUS:
      {
        Csp1RequestStatusBuffer *pReqStatus;
        cavium_dbgprint("Ioctl get request status called\n");
        pReqStatus = (Csp1RequestStatusBuffer *)arg; 
        ret = check_nb_command_id(pdev, (void *)track_list, pReqStatus->request_id);
        if(ret == ERR_REQ_PENDING)
        {
          pReqStatus->status = EAGAIN;
          ret = 0;
        }else
        {
          pReqStatus->status = ret;
          ret = 0;
        }
        cavium_dbgprint("get_request_status: 0x%x\n", pReqStatus->status);
      }
      break;
    case IOCTL_N1_GET_ALL_REQUEST_STATUS:
      {
        cavium_dbgprint("Ioctl getall request status called\n");
        /*check for completion of a series of pending requests*/
        ret = check_all_nb_command(pdev,(void *)track_list, (Csp1StatusOperationBuffer *)arg);
        cavium_dbgprint("getall request status ret:0x%x\n",ret);
      }
      break;
    case IOCTL_N1_FLUSH_ALL_CODE:
      {
        cavium_dbgprint("Ioctl flush all code called\n");
        /*SRIRAM cleanup_nb_command_pid(current->pid);*/
      }
      break;
    case IOCTL_N1_FLUSH_CODE:
      {
        cavium_dbgprint("Ioctl N1 Flush code called\n");
        /* SRIRAM cleanup_nb_command_id((Uint32)arg);*/
      }
      break;
    case IOCTL_N1_ALLOC_CONTEXT:
      {
        n1_context_buf c;
        cavium_dbgprint("ioctl N1 alloc context called\n");
        c = (*(n1_context_buf *)arg);
        c.ctx_ptr = alloc_context(pdev,(c.type));
        if (c.ctx_ptr == ~(Uint64)0) {
          cavium_print("ALLOC_CTX: failed \n");
          ret = -ENOMEM;   
        } else {
          ret = 0;
#ifdef CAVIUM_RESOURCE_CHECK
          {
            tracking_list *track_list = file->private_data;
            if(track_list) {
            cavium_spin_lock_softirqsave(&track_list->resource_lock);
            ret = insert_ctx_entry(pdev,&track_list->ctx_head, c.type,
                    c.ctx_ptr);
            cavium_spin_unlock_softirqrestore(&track_list->resource_lock);
           }
          }
#endif
          if(cavium_copy_out((caddr_t)arg, &c, sizeof(n1_context_buf)))
          {
            cavium_error("Failed to copy out context\n");
            ret = -EFAULT;
          }
        }
      }
      cavium_dbgprint("ioctl N1 alloc context returning\n");
      break;

    case IOCTL_N1_FREE_CONTEXT:
      {
        n1_context_buf c;
        cavium_dbgprint("ioctl N1 free context called\n");
        c = (*(n1_context_buf *)arg);
        dealloc_context(pdev, c.type, c.ctx_ptr);
        ret = 0;
#ifdef CAVIUM_RESOURCE_CHECK
        {
          tracking_list *track_list = file->private_data;
          struct cavium_list_head *tmp, *tmp1;
          if(track_list){
           cavium_spin_lock_softirqsave(&track_list->resource_lock);
          cavium_list_for_each_safe(tmp, tmp1, &track_list->ctx_head) {
            struct CTX_ENTRY *entry = list_entry(tmp, struct CTX_ENTRY, list);
            if (entry->ctx == c.ctx_ptr) 
            {
                cavium_list_del(&entry->list);
                cavium_free((Uint8 *)entry);
            }
          }
          cavium_spin_unlock_softirqrestore(&track_list->resource_lock);
         }
        }
#endif
      }
      cavium_dbgprint("ioctl N1 free context returning\n");
      break;
    case IOCTL_N1_SOFT_RESET_CODE:
      {
        Uint32 dev_id;         
        dev_id=(Uint32)arg;
        ret = do_soft_reset(&cavium_dev[dev_id]);
        ret = 0;
      }
      break;

    case IOCTL_N1_GET_STATUS_DDR:
      {
        Uint32 dev_id;
        dev_id=(Uint32)arg;

        if(cavium_dev[dev_id].dram_present)
          return 0;
        else
          return -1;
      }
      break;

    case IOCTL_N1_ALLOC_KEYMEM:
      {
        Uint64 key_handle;
        if (ssl == -1) {
          cavium_error ("Alloc Key Memory support only for SSL\n");
          return ERR_OPERATION_NOT_SUPPORTED;
        }
        cavium_dbgprint("ioctl N1 alloc keymem called\n");
        key_handle = alloc_key_memory(pdev);
        if (!key_handle) {
          cavium_error("Allocation of Key Memory failed\n");
          return -1;
        }
#ifdef CAVIUM_RESOURCE_CHECK
        {
          tracking_list *track_list = file->private_data;
          cavium_spin_lock_softirqsave(&track_list->resource_lock);
          ret = insert_key_entry(pdev,&track_list->key_head, 
                key_handle);
          cavium_spin_unlock_softirqrestore(&track_list->resource_lock);
        }
#endif
        if(cavium_copy_out((caddr_t)arg, &key_handle, sizeof(Uint64)))
          cavium_error("Failed to copy out key_handle\n");
      }
      cavium_dbgprint("ioctl N1 alloc keymem returning.\n");
      break;
    case IOCTL_N1_FREE_KEYMEM:
      {
        n1_write_key_buf key_buf;
        if (ssl == -1) {
          cavium_error ("Key Memory support only for SSL\n");
          return ERR_OPERATION_NOT_SUPPORTED;
        }
        cavium_dbgprint("ioctl N1 free keymem called\n");
        key_buf = (*(n1_write_key_buf *)arg);
        dealloc_key_memory(pdev, key_buf.key_handle);
#ifdef CAVIUM_RESOURCE_CHECK
        {
          tracking_list *track_list = file->private_data;
          struct cavium_list_head *tmp, *tmp1;
          if(track_list){
          cavium_spin_lock_softirqsave(&track_list->resource_lock);
          cavium_list_for_each_safe(tmp, tmp1, &track_list->key_head) {
            struct KEY_ENTRY *entry = list_entry(tmp, struct KEY_ENTRY, list);
            if (entry->key_handle == key_buf.key_handle) 
            {
                cavium_list_del(&entry->list);
                cavium_free((Uint8 *)entry);
            }
          }
          cavium_spin_unlock_softirqrestore(&track_list->resource_lock);
         }
        }
#endif
      }
      cavium_dbgprint("ioctl N1 free keymem returning.\n");
      break;
    case IOCTL_N1_WRITE_KEYMEM:
      {
        n1_write_key_buf key_buf;
        Uint8 *key;
        if (ssl == -1) {
          cavium_error ("Key Memory support only for SSL\n");
          return ERR_OPERATION_NOT_SUPPORTED;
        }
        key_buf = (*(n1_write_key_buf *)arg);
        key = (Uint8*)get_buffer_from_pool(pdev,key_buf.length);
        if (key == NULL) {
          cavium_error("Unable to allocate memory for key\n");
          return -1;
        }
        if(cavium_copy_in(key, CAST_FRM_X_PTR(key_buf.key), key_buf.length))
        {
          cavium_error("Unable to copy in key\n");
          return -1;
        }
        key_buf.key = CAST_TO_X_PTR(key);
        if (store_key_mem(pdev, key_buf, UCODE_IDX) < 0) 
        {
          cavium_error("n1_ioctl: store_key_mem failed\n");
          put_buffer_in_pool(key,key_buf.length);
          return -1;
        }
        put_buffer_in_pool(key,key_buf.length);
        ret = 0;
      }
      break;

    case IOCTL_N1_GET_DEV_TYPE:
      {
        *((Uint32 *)arg) = pdev->device_id; 

      }
      break;

    case IOCTL_N1_GET_RANDOM_CODE:
      {
         n1_operation_buffer *buf;
        if(!pdev->enable)
        {
          ret = ERR_DRIVER_NOT_READY;
          break;
        }
        buf = (n1_operation_buffer *)arg;
        ret = do_operation(pdev, buf,(void *)track_list);
      }
      break;
    case IOCTL_N1_INIT_CODE:
      {
	if (init_flag && nplus && pdev->device_id==N3_DEVICE)
		break;
       if (n3_vf_driver) {
               if (nplus || ssl > 0 || ipsec > 0) {
                       cavium_dbgprint("Calling VF nplus init\n");
          ret = nplus_init(pdev, BOOT_IDX, arg);
		} else {
			ret = do_init(pdev);
		}
        }
        else {
               if (nplus || ssl > 0 || ipsec > 0) {
                       cavium_dbgprint("calling nplus_init\n");
                       ret = nplus_init(pdev, BOOT_IDX, arg);
               } else {
          int boot_info = 0;
          int offset = 0;
          int mainline_info = 0;
          Uint8 code_type;
          int i;
          struct MICROCODE *microcode;

          init_buffer = (Csp1InitBuffer *)arg;

          microcode = pdev->microcode;

          boot_info = 0;
          mainline_info = 0;

          /* get all the information from init buffer */
          for(i=0;i<init_buffer->size;i++)
          {
            code_type = init_buffer->version_info[i][0];

            if(code_type == CODE_TYPE_BOOT)
            {
                if(boot_info)
                {
                    cavium_print( "Code type boot found more than once\n");
                    ret = ERR_INIT_FAILURE;
                    break;
                }
                else
                {
                    cavium_print( "got boot microcode\n");
                    boot_info=1;
                }
            }
            else if (code_type == CODE_TYPE_MAINLINE)
            {
                if(mainline_info)
                {
                    cavium_print( "Code type mainline found more than once\n");
                    ret = ERR_INIT_FAILURE;
                    break;
                }
                else
                {
                    cavium_print( "got mainline microcode\n");
                    mainline_info=1;
                }
            }
            else
            {
                cavium_print( "unknown microcode type\n");
                ret = ERR_INIT_FAILURE;
                break;
            }

            /* code */

            microcode[i].code_type = code_type;
            microcode[i].code_size = init_buffer->code_length[i];
            microcode[i].code = 
                (Uint8 *)get_buffer_from_pool(pdev, microcode[i].code_size);

            if (microcode[i].code == NULL)
            {
                cavium_print( "Failed to allocate %d bytes microcode buffer type %d\n", 
                    microcode[i].code_size, code_type);
                ret = ERR_MEMORY_ALLOC_FAILURE;
                break;
            }            

            if(cavium_copy_in(microcode[i].code,
                    CAST_FRM_X_PTR(init_buffer->code[i]),
                    microcode[i].code_size))
            {
                cavium_error("Failed to copy microcode->code for microcode %d\n", i);
                ret = ERR_INIT_FAILURE;
                break;
            }

            /* data */
            microcode[i].data_size = init_buffer->data_length[i];
            if(microcode[i].data_size)
            {
#ifdef MC2
                offset = 40;
#else
                offset = 0;
#endif
                microcode[i].data =  (Uint8 *)cavium_malloc_nc_dma(pdev,
                    microcode[i].data_size+offset,
                    &microcode[i].data_dma_addr);

                if (microcode[i].data == NULL)
                {
                    cavium_print( "Failed to allocate %d bytes cst buffer type %d\n", 
                        microcode[i].data_size,code_type);

                    ret = ERR_MEMORY_ALLOC_FAILURE;
                    break;
                } 
                cavium_memset(microcode[i].data, 0x0,
                    microcode[i].data_size + offset);


                if(cavium_copy_in( microcode[i].data + offset,
                        CAST_FRM_X_PTR(init_buffer->data[i]),
                        microcode[i].data_size))
                {
                    cavium_error("Failed to copy in microcode->data for microcode %d\n", i);
                    cavium_free_nc_dma(pdev,
                        microcode[i].data_size+offset,
                        microcode[i].data,
                        microcode[i].data_dma_addr);
                    microcode[i].data_size = 0;
                    microcode[i].data = NULL;
                    microcode[i].data_dma_addr = 0;

                    ret = ERR_INIT_FAILURE;
                    break;
                }
            }

            /* sram address */
            if(cavium_copy_in(microcode[i].sram_address, 
                    init_buffer->sram_address[i],
                    SRAM_ADDRESS_LEN))
            {
                cavium_error("Failed to copy in sram_address for microcode %d\n", i);
                cavium_free_nc_dma(pdev, microcode[i].data_size+offset,
                    microcode[i].data,
                    microcode[i].data_dma_addr);
                microcode[i].data_size = 0;
                microcode[i].data = NULL;
                microcode[i].data_dma_addr = 0;

                ret = ERR_INIT_FAILURE;
                break;
            }


            cavium_print("Code type = %02x, code size = %x, data size = %x\n",
                    microcode[i].code_type,
                    microcode[i].code_size,
                    microcode[i].data_size);


          }/* for */

          /* check for any missing piece */
          if( !mainline_info || !boot_info ) {
            cavium_print( "Not all of the information was sent to device driver.\n");
            cavium_print( "Please check version information\n");
            ret = ERR_INIT_FAILURE;
            break;
          }

          /* Now we have gathered all the required information from init_buffer*/
          /* Now it is time for some action. */
          ret = do_init(pdev);
        } /* nplus */
       }
        break;
      }
    case IOCTL_N1_GET_DEV_CNT:
      {
        n1_dev_mask *buf;
        Uint8 i=0;
        Uint16 mask=0;   
        buf=(n1_dev_mask*)arg;   
        cavium_dbgprint("Ioctl GET device count called\n");
        /*retun the devices detected*/
        buf->dev_cnt=dev_count;   

        for(i=0;i<dev_count;i++)
        {   
          if(cavium_dev[i].enable)
            mask |=   1<<i;    
        }

        buf->dev_mask=mask;
        //  *((Uint32 *)arg) = dev_count;
        break;
      }

      /* To driver state */
    case IOCTL_N1_GET_DRIVER_STATE:
      {
        uint8_t *driver_type = (uint8_t *)arg;
        cavium_dbgprint("ioctl get driver type\n");

        if (nplus) /* if ssl & ipsec are running */
          *driver_type = DRV_ST_SSL_IPSEC;
        else if (ssl>0) /* if ssl running on some cores */ 
          *driver_type = DRV_ST_SSL_CORES;
        else if (ssl==0) /* if ssl running on default cores */
          *driver_type = DRV_ST_SSL_DFL;
        else if (ipsec>0) /* if ipsec running on some cores */
          *driver_type = DRV_ST_IPSEC_CORES;
        else if (ipsec==0) /* if ipsec running on default cores */
          *driver_type = DRV_ST_IPSEC_DFL;
        else /* Unknown state */
          *driver_type = DRV_ST_UNKNOWN;
      }
      break;

    case IOCTL_CSP1_GET_CORE_ASSIGNMENT:
      if (nplus || ssl>0 || ipsec>0)
      {
        int i;
        Csp1CoreAssignment *core_assign = (Csp1CoreAssignment *)arg;

        cavium_dbgprint("ioctl Get core assignment \n");
        cavium_spin_lock_softirqsave(&pdev->mc_core_lock);

        for(i=0;i<MICROCODE_MAX-!nplus;i++)
        {
          core_assign->core_mask[i] = get_core_mask(pdev,i); 
         if (n3_vf_driver)
               core_assign->mc_present[i] = 1;
         else
          core_assign->mc_present[i] = (pdev->microcode[i].code==NULL)? 0:1;
        }
        cavium_spin_unlock_softirqrestore(&pdev->mc_core_lock);
      }
      break;

    case IOCTL_CSP1_SET_CORE_ASSIGNMENT:
      if(init_flag && nplus && (pdev->device_id==N3_DEVICE))
      {
      	//For core migration
      	int j;
	Uint64 core_mask, changed_mask;
	Uint32 station_core_en[4];
	Uint32 i;
	int id;
	Csp1CoreAssignment *core_assign = (Csp1CoreAssignment *) arg;

	
	//Get the change
	changed_mask = 0;

   	for(i=0;i<MICROCODE_MAX - !nplus; i++)
	{
		core_mask = get_core_mask(pdev, i);
		changed_mask |= (core_mask ^ core_assign->core_mask[i]);
	}
	
	//Disable "changed" exec units from getting requests
	change_exec_mask_n3(pdev, changed_mask, 0); 

	//Remove the changed cores from their core groups
	for(j=0; j < NITROX_PX_MAX_GROUPS; j++)
	{
		Uint32 temp_lo, temp_hi;
		Uint64 temp;
		if(npx_group_is_used(j))

		{
			read_PKP_register(pdev,(pdev->CSRBASE_A+ N3_IQMQ_GRP0_EXECMSK_LO)+
							(Uint32)(j<<8),&temp_lo);
			read_PKP_register(pdev,(pdev->CSRBASE_A+ N3_IQMQ_GRP0_EXECMSK_HI)+
							(Uint32)(j<<8),&temp_hi);
			temp = temp_lo | (((Uint64)(temp_hi)) << 32);
			if(temp & changed_mask)
			{
			    temp_lo &= ~((changed_mask << 32) >> 32);
			    temp_hi &= ~(changed_mask >> 32);	
			    write_PKP_register(pdev, 
					      (pdev->CSRBASE_A + N3_IQMQ_GRP0_EXECMSK_LO)
							+(Uint32)(j<<8),temp_lo);
			    write_PKP_register(pdev, 
					      (pdev->CSRBASE_A + N3_IQMQ_GRP0_EXECMSK_HI)
							+(Uint32)(j<<8),temp_hi);
			}
 
		}
	}


	//initialize the station_core_en values
	for(i=0; i<4; i++)
	{
	   read_PKP_register(pdev, (pdev->CSRBASE_A + N3_CORE_EN_0 + (i*0x10000)), &station_core_en[i]);
	}

	//Wait till all "changed" cores are no longer busy
	for(id=0; id < 64; id++)
	{
	  if(changed_mask & ((Uint64)1<<id))
	  {
	    //We have to check core number "id"
	    Uint8 core, station;
	    Uint32 reg, reg_value;
	    core = id/4;
	    station = id % 4; 
	    reg = 0x400F8 + 0x800 * core + (station * 0x10000);
	    //loop till core not busy
	    do {
	      read_PKP_register(pdev, (pdev->CSRBASE_A + reg), &reg_value);
	    } while((reg_value & (((Uint32)1) << 30)));   
	    //now add this core to the appropriate station_core_en
	    station_core_en[station] &= ~(1 << core);


	  }
	}

	//Disable appropriate cores
	for(i=0; i<4; i++)
	{
	   write_PKP_register(pdev, (pdev->CSRBASE_A + N3_CORE_EN_0 + (i*0x10000)), station_core_en[i]);
	}
/* 	for(id =0; id<64; id++)
	{
		
		if(((Uint64)1<<id) & changed_mask)
		{
		   Uint32 exec_avail = 0x30070 + (id << 8);
		   Uint32 dwval;
		   do
		   {
		      read_PKP_register(pdev, (pdev->CSRBASE_A + exec_avail), &dwval);
		   } while(!( dwval & 0x1 ));			
		}
        }
*/
	for(i=FREE_IDX+1; i<MICROCODE_MAX-!nplus; i++)
	{
	    Uint32 temp_lo, temp_hi;	    
    	    core_mask = core_assign->core_mask[i] & changed_mask; //SSL/IPSEC core mask

    	    if(pdev->cavfns.load_microcode(pdev, i))
	    {
	    	cavium_print("Error loading microcode %d\n", i);
		ret = ERR_UCODE_LOAD_FAILURE;
		goto error_set_cores;
	    }

    	    for(id=0; id < 64; id++)
    	    {
    		if( ((Uint64)1<<id) & core_mask)
     		    station_core_en[ id % 4 ] |= (((Uint32)1) << (id/4));
    	    }
    	    for(j=0; j<4; j++)
    	    {
     		write_PKP_register(pdev, (pdev->CSRBASE_A + N3_CORE_EN_0 + (j*0x10000)), station_core_en[j]);
    	    }
	    mdelay(1);    
	    //Assign new cores to proper core group
	    //Find core_grp for this i
	    j = pdev->microcode[i].core_grp;
	    //Add the new cores to its new core group

   	    read_PKP_register(pdev,(pdev->CSRBASE_A+ N3_IQMQ_GRP0_EXECMSK_LO)+(Uint32)((j)<<8), 
					  &temp_lo);
	    read_PKP_register(pdev,(pdev->CSRBASE_A+ N3_IQMQ_GRP0_EXECMSK_HI)+(Uint32)((j)<<8), 
	 				  &temp_hi);
	     
	    temp_lo |= (core_mask << 32) >> 32;
	    temp_hi |= (core_mask >> 32);
	    write_PKP_register(pdev,(pdev->CSRBASE_A+ N3_IQMQ_GRP0_EXECMSK_LO)+(Uint32)((j)<<8), 
					   temp_lo);
	    write_PKP_register(pdev,(pdev->CSRBASE_A+ N3_IQMQ_GRP0_EXECMSK_HI)+(Uint32)((j)<<8), 
					   temp_hi);
	}

	core_mask = ( core_assign->core_mask[1] & changed_mask) | ( core_assign->core_mask[2] & changed_mask);
        change_exec_mask_n3(pdev, core_mask, 1);
    
    	//Migration complete, now newly assigned cores can start getting requests
    	//Assign appropriate variables(which are important for next core migrtn) and exit
	for(i=FREE_IDX; i < MICROCODE_MAX - !nplus; i++)
	{
	    Uint8 next_id = -1, prev_id = -1;
	    Uint8 id;
	    id = pdev->microcode[i].core_id;
	    if(id == (Uint8)-1)
		continue;
	    next_id = pdev->cores[id].next_id;
	    while(id != (Uint8)(-1))
	    {
    		if( ((Uint64)1 << id) & (changed_mask & ~(core_assign->core_mask[i])))
    		{
		    //Step1 : Remove this core from previous list
    		    if(prev_id == (Uint8)(-1))
    		    {
    			//This id is the first in the list
    			pdev->microcode[i].core_id = next_id;	
    		    }
	    	    else
	    	    {
			//Connect id's previous to id's next
			pdev->cores[prev_id].next_id = next_id;
    		    }
		    pdev->cores[id].next_id = -1;
		    //Step2: Put this core in its appropriate list
		    for(j=FREE_IDX; j < MICROCODE_MAX - !nplus; j++)
		    {
			if(j == i) continue;
			if(core_assign->core_mask[j] & ((Uint64)1<<id))
			{
			    //found its place
			    //insert this core into the front of the list
			    pdev->cores[id].next_id = pdev->microcode[j].core_id;
			    pdev->microcode[j].core_id = id;
			    break;
			}
		    }
		    prev_id = prev_id;
		    id = next_id;
    		}
		else
		{
		    //Don't touch this core
		    prev_id = id;
		    id = next_id;		    
		}
		if(id != (Uint8)(-1))
    		    next_id = pdev->cores[id].next_id;
	    }
	}
	ret= 0;
	break;

error_set_cores:
	ret= 1;
	break;       
      }
      else if (nplus || ipsec>0 || ssl>0)
      {
        int i;
        Uint8 id;
        Uint64 changed_mask_0_1 = 0, changed_mask_1_0 = 0;
        Uint64 core_mask, core_mask_1_0, core_mask_0_1;
        Csp1CoreAssignment *core_assign = (Csp1CoreAssignment *)arg;
        Uint8   core_grp=0;
        Uint32  new_core_grp_mask=0, reg_exec_grp_mask=0;
        cavium_dbgprint("ioctl set core assignment \n");
        
	if(pdev->initialized != 1)
        {
          ret = ERR_DRIVER_NOT_READY;
          break;
        }

        cavium_dbgprint("Assign Cores(%ld): { ", jiffies);
        for(i=0;i<MICROCODE_MAX - !nplus; i++) {
          cavium_dbgprint("%llx ", core_assign->core_mask[i]);
          if (i==1) {
             if(ssl > 0) ssl_cores=core_assign->core_mask[i];
             else ipsec_cores = core_assign->core_mask[i];
          }
          else
             if(i==2) ipsec_cores = core_assign->core_mask[i];
        }

        cavium_dbgprint("}\n");

        cavium_spin_lock_softirqsave(&pdev->mc_core_lock);
        /* This loop checks if the new assignments will be valid */
        for(i=0;i<MICROCODE_MAX - !nplus && ret==0;i++)
        {
          /*  Check the 0->1 transitions in the mask */
          core_mask = get_core_mask(pdev,i);
          core_mask_0_1 = (~core_mask & core_assign->core_mask[i]);
          if(core_mask_0_1)
          {
            if(changed_mask_0_1 & core_mask_0_1)
            {
                ret = ERR_ILLEGAL_ASSIGNMENT;
                goto cleanup_set_cores;
            }
            changed_mask_0_1 |= core_mask_0_1;
          }

          core_mask_1_0 = (core_mask & ~core_assign->core_mask[i]);
          if(core_mask_1_0)
          {
            /*  Check the 1->0 transitions in the mask */
            if(changed_mask_1_0 & core_mask_1_0)
            {
                ret = ERR_ILLEGAL_ASSIGNMENT;
                goto cleanup_set_cores;
            }
            changed_mask_1_0 |= core_mask_1_0;
            /* If we are reducing the cores to 0 for any microcode, there
             * should not be any open handles for that microcode */
            /*               if((core_assign->core_mask[i] == 0)
                     && pdev->microcode[i].use_count)
                     {
                     ret = ERR_ILLEGAL_ASSIGNMENT;
                     goto cleanup_set_cores;
                     } */
          }
        }
        /* Make sure the transitions match */
        if(changed_mask_1_0 != changed_mask_0_1)
        {
          ret = ERR_ILLEGAL_ASSIGNMENT;
          goto cleanup_set_cores;
        }

        /* We will first free cores */
        for(i=FREE_IDX+1; i<MICROCODE_MAX-!nplus; i++)
        {
          Uint8 prev_id = (Uint8)-1;
          if(!(changed_mask_1_0 & get_core_mask(pdev, i)))
            continue;

          id = pdev->microcode[i].core_id;
          while(id != (Uint8)-1)
          {
            /* Is this core to be free'd ? */
            if(changed_mask_1_0 & (1<<id))
            {
                /* First get the core to a "loop forever state" */
                if(pdev->microcode[i].code_type == CODE_TYPE_MAINLINE)
                {
                    if(acquire_core(pdev, i, id))
                    {
                    /* TODO: Need to consider error handling. */
                    cavium_print("Failed core %d acquisition!!\n", id);
                    }
                }
                /* Delink from current list */
                if(prev_id == (Uint8)-1)
                    pdev->microcode[i].core_id = pdev->cores[id].next_id;
                else
                    pdev->cores[prev_id].next_id = pdev->cores[id].next_id;

                /* Add to free list */
                pdev->cores[id].next_id=pdev->microcode[FREE_IDX].core_id;
                pdev->microcode[FREE_IDX].core_id = id; 
                pdev->cores[id].ucode_idx = FREE_IDX;

                if(prev_id == (Uint8) -1)
                    id = pdev->microcode[i].core_id;
                else
                    id = pdev->cores[prev_id].next_id;
            }
            else
            {
                prev_id = id; id = pdev->cores[prev_id].next_id;
            }
          }
          /* Initially all microcode have core grp as NITROX_PX_MAX_GROUPS.
             We need to free the group only if the microcode was previously
             loaded but is being unloaded now. */
          if((pdev->device_id  == NPX_DEVICE || pdev->device_id == N3_DEVICE)&& pdev->microcode[i].core_grp < NITROX_PX_MAX_GROUPS) {
            free_npx_group(pdev->microcode[i].core_grp);
          }
        }

        /* TODO: We need to be sure they are done */
        /* Disable the cores */
        cavium_udelay(10);

        cavium_print("Disabling units: mask 0x%llx\n", changed_mask_1_0);

        pdev->cavfns.disable_exec_units_from_mask(pdev, changed_mask_1_0);
        boot_time=1;
        if(pdev->device_id == N3_DEVICE)
            disable_exec_masks_n3(pdev);
        /* Now go ahead and add the cores to the new microcodes */
        for(i=FREE_IDX+1; i<MICROCODE_MAX-!nplus; i++)
        {

          Uint8 prev_id = (Uint8)-1;
          Uint64 mask = 0;

          if(pdev->device_id == NPX_DEVICE || pdev->device_id==N3_DEVICE)
          {
            core_grp = (Uint8)get_next_npx_group();
            if(core_grp >= NITROX_PX_MAX_GROUPS) {
                cavium_error("N1_IOCTL : No more core groups available\n");
                return ERR_ILLEGAL_ASSIGNMENT;
            }
            pdev->microcode[i].core_grp = core_grp;
		cavium_dbgprint("%s: %d: pdev->microcode[%d]->core_grp:%d\n", __func__, __LINE__, i, core_grp);
          }

          if(!(changed_mask_0_1 & core_assign->core_mask[i]))
            continue;

          cavium_print("Loading ucode %d\n", i);

          /* Load the microcode, except for FREE_IDX */
          if(pdev->cavfns.load_microcode(pdev, i))
          {
            cavium_print("Error loading microcode %d\n", i);
            ret = ERR_UCODE_LOAD_FAILURE;
            goto cleanup_set_cores;
          }
#if 0
          if(pdev->device_id == NPX_DEVICE || pdev->device_id==N3_DEVICE)
          {
            core_grp = (Uint8)get_next_npx_group();
            if(core_grp >= NITROX_PX_MAX_GROUPS) {
                cavium_error("N1_IOCTL : No more core groups available\n");
                return ERR_ILLEGAL_ASSIGNMENT;
            }
            pdev->microcode[i].core_grp = core_grp;
          }
#endif
          id = pdev->microcode[FREE_IDX].core_id;
          while(id != (Uint8)-1)
          {
            /* Is this core to be allocated ? */
            if(changed_mask_0_1 & core_assign->core_mask[i] & (((Uint64)1)<<id))
            {
                /* Delink from free list */
                if(prev_id == (Uint8)-1)
                    pdev->microcode[FREE_IDX].core_id
                    = pdev->cores[id].next_id;
                else
                    pdev->cores[prev_id].next_id
                    = pdev->cores[id].next_id;

                /* Add to microcode list */
                pdev->cores[id].next_id=pdev->microcode[i].core_id;
                pdev->microcode[i].core_id = id; 
                pdev->cores[id].ucode_idx = i;
                new_core_grp_mask |= ( (((Uint64)1) << core_grp) << (id * 4));
                mask |= (((Uint64)1)<<id);

                if(prev_id == (Uint8) -1)
                {
                    id = pdev->microcode[FREE_IDX].core_id;
                }
                else
                {
                    id = pdev->cores[prev_id].next_id;
                }
            }
            else
            {
                prev_id = id; id = pdev->cores[prev_id].next_id;
            }
          }

          cavium_dbgprint("Cycling cores: 0x%llx\n", mask);

          cavium_udelay(100);
          pdev->cavfns.enable_exec_units_from_mask(pdev, mask);
	  if(pdev->device_id == N3_DEVICE)
          {
	     core_mask = get_core_mask(pdev, 1) | get_core_mask(pdev, 2);
	     change_exec_mask_n3(pdev, core_mask, 2);
             enable_exec_masks_n3(pdev); //line taken from pf_vf_merged_driver
             new_core_grp_mask=0xffffffff;
             write_PKP_register(pdev,(pdev->CSRBASE_A+ N3_IQMQ_GRP0_EXECMSK_LO)+(Uint32)(core_grp<<8), (Uint32)(mask & new_core_grp_mask));
            write_PKP_register(pdev,(pdev->CSRBASE_A+ N3_IQMQ_GRP0_EXECMSK_HI)+(Uint32)(core_grp<<8), (Uint32)((mask>>32) & new_core_grp_mask));
         }
        }
        cavium_udelay(100);


        if(pdev->device_id == NPX_DEVICE)
        {
          read_PKP_register(pdev, (pdev->CSRBASE_A + REG_EXEC_GROUP), &reg_exec_grp_mask);
          reg_exec_grp_mask |= new_core_grp_mask;
          write_PKP_register(pdev, (pdev->CSRBASE_A + REG_EXEC_GROUP), reg_exec_grp_mask);
        }

cleanup_set_cores:
        cavium_spin_unlock_softirqrestore(&pdev->mc_core_lock);
        if(ret != 0) break;

        if(pdev->enable == 0)
        {
          int idx;

          /* TODO: Assuming that MLM code is running (may not be true)
           * We will first search for the MLM code type. */
          for(idx=0;idx<MICROCODE_MAX-!nplus;idx++)
          {
            if(pdev->microcode[idx].code_type == CODE_TYPE_MAINLINE)
                break;
          }
          if(idx>=MICROCODE_MAX)
          {
            /* We did not find any mainline microcode, so we give up */
            ret = ERR_INIT_FAILURE;
            break;
          }

          /* Now initialize encrypted master secret key and iv in the first 48
           * bytes of FSK */
          //if(ssl>=0 && core_assign->core_mask[UCODE_IDX])  
          {    
            if(init_ms_key(pdev, UCODE_IDX))
            {
                cavium_print("Couldnot initialize encrypted master secret key and IV.\n");
                ret = ERR_INIT_FAILURE;
                break;
            }
          }   
          boot_time=0;
          if(pdev->device_id == N3_DEVICE && !n3_vf_driver) {
       		if(vf_count > 0){
			uint32_t dwval;
			pdev->cavfns.disable_request_unit(pdev);
			enable_exec_masks_n3(pdev);
			pci_enable_sriov(pdev->dev, vf_count);
			read_PKP_register(pdev, (pdev->CSRBASE_A + N3_CMD_REG), &dwval);
			dwval |= (pf_vf[vf_count/8] << 24);
			write_PKP_register(pdev, (pdev->CSRBASE_A + N3_CMD_REG), dwval);
		} else 
			enable_exec_masks_n3(pdev);
	  }
	  //init_flag = 1;
          pdev->enable=1;
        }
        ret=0;
      }
      break;


      /* Oops, sorry */
    default:
      cavium_print("cavium: Invalid request 0x%x\n", cmd);
      ret = -EINVAL;
      break;

  } /* switch cmd*/
  return (ret);

}/*n1_ioctl*/



extern Uint64 cavium_command_timeout;
Uint64 get_next_addr(cavium_device *pkp_dev, int q_no);
void do_post_process(cavium_device *n1_dev, n1_user_info_buffer *user_info);

/*
 * Poll for completion
 */
unsigned int
n1_poll(struct file *fp, poll_table *wait)
{
	Uint32 mask = 0, is_ready = 0;
	struct cavium_list_head *tmp, *tmp1;
	Uint8 status = 0;
	cavium_device* dev;
	n1_user_info_buffer* user_info = NULL;
	tracking_list* track_list = (tracking_list*)fp->private_data;
	if (!track_list || !track_list->pending) {
		return 0;
	}

	cavium_spin_lock_softirqsave(&track_list->nbl_lock);
	cavium_list_for_each_safe(tmp, tmp1, &track_list->nbl) {
		user_info = list_entry(tmp, n1_user_info_buffer, list);
		if (!user_info) {
			printk (KERN_CRIT "user_info is NULL\n");
			continue;
		}
		status = (Uint8)*((Uint8*)user_info->completion_addr);
		if ((status == 0xff) && ((user_info->time_in + cavium_command_timeout) > (Uint64)cavium_jiffies)) {
			cavium_print ("RequestId %d pending\n", user_info->request_id);
			continue;
		}
		if (status== 0xff) {
			Uint32 dwval = 0, dwval1 = 0, rval = 0, wval = 0;
			dev = user_info->n1_dev;
			if (dev->device_id == NPX_DEVICE) {
				read_PKP_register (dev, (dev->CSRBASE_A + 0x208+ (user_info->queue * 0x10)), &dwval);
                read_PKP_register (dev, (dev->CSRBASE_B + REQ0_BASE_LOW + (user_info->queue *0x20)), &dwval1);
				rval= (dwval - dwval1) / COMMAND_BLOCK_SIZE;
			} else if (dev->device_id == N3_DEVICE) {
				Uint64 read = get_next_addr (dev, user_info->queue);
				Uint8* rptr = bus_to_virt (read);
				dwval = (Uint32)(rptr - ((Uint8*)(ptrlong)dev->command_queue_base[user_info->queue]));
				rval = dwval / COMMAND_BLOCK_SIZE;
			}
			wval = dev->command_queue_front[user_info->queue] - dev->command_queue_base[user_info->queue];
			wval = wval / COMMAND_BLOCK_SIZE;
			dwval = user_info->index;
			if (((wval > rval) && (rval <= dwval)) || !((wval<dwval) && (dwval <= rval))) {
				user_info->time_in = cavium_jiffies;
				cavium_print ("RequestID %d pending\n", user_info->request_id);
				continue;
			}
		}
		is_ready = 1;
		cavium_list_del (&user_info->list);
		track_list->pending--;

		if (status == 0xff) {
			mask = ERR_REQ_TIMEOUT;
			cavium_error(" REQUEST TIMED OUT\n");
		} else {
			mask = (Uint32)status;
		}
		if (user_info->status) {
			dev = user_info->n1_dev;
			if (user_info->cmd_data) {
				cavium_spin_lock_softirqsave(&(dev->pending_queue[user_info->queue].pending_lock));   
				user_info->cmd_data->done = 1;
				cavium_spin_unlock_softirqrestore(&(dev->pending_queue[user_info->queue].pending_lock));   
			}
		}
		user_info->status = mask; 

		dev = &cavium_dev[next_dev];
		next_dev = (next_dev + 1) % dev_count;
		do_post_process (dev, user_info);
    }
	cavium_spin_unlock_softirqrestore(&track_list->nbl_lock);

  if (is_ready) {
    mask = POLLIN | POLLRDNORM;
  }

  return mask;
}


#ifndef CAVIUM_NO_MMAP
/* 
 *  VMA Operation called when an munmap of the entire VM segment is done
 */

  void 
n1_vma_close(struct vm_area_struct *vma)
{
  Uint32 size;
  ptrlong virt_addr;
  Uint8 *kmalloc_ptr, *kmalloc_area;
  Uint32 minor=0;
  if (!nplus)
    minor = MINOR(vma->vm_file->f_dentry->d_inode->i_rdev);

  kmalloc_ptr = vma->vm_private_data;
  size = vma->vm_end - vma->vm_start;

  /* align it to page boundary */
  kmalloc_area = (Uint8 *)(((ptrlong)kmalloc_ptr + PAGE_SIZE -1) & PAGE_MASK);

  /* Unreserve all pages */
  for(virt_addr = (ptrlong)kmalloc_area; 
      virt_addr < (ptrlong)kmalloc_area + size; virt_addr +=PAGE_SIZE) {
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,0) 
    mem_map_unreserve(virt_to_page(virt_addr));
#else
    ClearPageReserved(virt_to_page(virt_addr));
#endif
  }

  put_buffer_in_pool(kmalloc_ptr,size);

  cavium_dbgprint( "pkp_drv: UNmap returning successfully(pid=%d)\n",
      current->pid);
  CAVIUM_MOD_DEC_USE_COUNT;
  return;

}

static struct vm_operations_struct n1_vma_ops = 
{
  NULL,
  n1_vma_close,
  NULL,
};


/*
 * mmap entry point
 */
  int 
n1_mmap(struct file *file, struct vm_area_struct *vma)
{
  Uint32 size;
  Uint8 *kmalloc_ptr,*kmalloc_area;
  ptrlong virt_addr;
  Uint32 offset;
  Uint32 minor=0;
  if (ssl==0 || ipsec==0)
    minor = MINOR(file->f_dentry->d_inode->i_rdev);
  MPRINTFLOW();

  size = vma->vm_end - vma->vm_start;

  if(size % PAGE_SIZE) {
    cavium_error("n1_mmap: size (%d) not multiple of PAGE_SIZE.\n", size);
    return -ENXIO;
  }

  offset = vma->vm_pgoff << PAGE_SHIFT;
  if(offset & ~PAGE_MASK) {
    cavium_error("n1_mmap: offset (%d) not aligned.\n", offset);
    return -ENXIO;
  }

  kmalloc_ptr = (Uint8 *)get_buffer_from_pool(&cavium_dev[minor], size);
  if(kmalloc_ptr == NULL) {
    cavium_error("n1_mmap: not enough memory.\n");
    return -ENOMEM;
  }

  /* align it to page boundary */
  kmalloc_area = (Uint8 *)(((ptrlong)kmalloc_ptr + PAGE_SIZE -1) & PAGE_MASK);

  /* reserve all pages */
  for (virt_addr = (ptrlong)kmalloc_area; 
      virt_addr < (ptrlong)kmalloc_area + size; virt_addr +=PAGE_SIZE) {
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,0) 
    mem_map_reserve(virt_to_page(virt_addr));
#else
    SetPageReserved(virt_to_page(virt_addr));
#endif
    /*  get_page not required *
        get_page(virt_to_page(virt_addr)); */
  }

  /* Mark the vm-area Reserved*/
  vma->vm_flags |=VM_RESERVED;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
  if(remap_pfn_range(vma,vma->vm_start,
        (virt_to_phys((void *)(ptrlong)kmalloc_area))>>PAGE_SHIFT,
        size, vma->vm_page_prot))

#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2,4,18) 
    if(remap_page_range(vma->vm_start,
          virt_to_phys((void *)(ptrlong)kmalloc_area),
          size, vma->vm_page_prot))
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,20) 
      if(remap_page_range(vma,vma->vm_start,
            virt_to_phys((void *)(ptrlong)kmalloc_area),
            size, vma->vm_page_prot))
#endif
      {

        cavium_error("n1_mmap: remap page range failed.\n");
        return -ENXIO;
      }

  vma->vm_ops = &n1_vma_ops;
  vma->vm_private_data = kmalloc_ptr;
  vma->vm_file = file;

  CAVIUM_MOD_INC_USE_COUNT;
  cavium_dbgprint( "n1_mmap: mmap returning successfully(pid=%d)\n",current->pid);
  return 0;
}

#endif


/*
 * Linux layer Interrupt Service Routine for intx
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19))
irqreturn_t linux_layer_isr(int irq, void *dev_id, struct pt_regs *regs)
#else
irqreturn_t linux_layer_isr(int irq, void *dev_id)
#endif
{
#ifdef INTERRUPT_RETURN
  int ret=0;
  cavium_device *pdev=(cavium_device *)dev_id;
#ifdef MSIX_ENABLED
  ret = pdev->cavfns.interrupt_handler(irq, dev_id);
#else
  ret = pdev->cavfns.interrupt_handler(dev_id);
#endif
  if(ret == 0) {
    return IRQ_HANDLED;
  }else {
    return IRQ_NONE;
  }
#else
  cavium_device *pdev=(cavium_device *)dev_id;
  pdev->cavfns.interrupt_handler(dev_id);
#endif
}

/* 
 * Hook the interrupt handler
 */
int setup_interrupt(cavium_device *pdev)
{
  int result=0;
  int interrupt_pin;
#ifdef MSIX_ENABLED
  int numvecs, i;
#endif

  MPRINTFLOW();
#ifdef CONFIG_PCI_MSI
  if(pdev->device_id==NPX_DEVICE ){   
    if(pci_find_capability((struct pci_dev *)(pdev->dev), PCI_CAP_ID_MSI)) {
      if(!pci_enable_msi((struct pci_dev *)(pdev->dev))) {
        msi_enabled = 1;
      }
    } 
  }   


#ifdef MSIX_ENABLED
//Only N3 supports MSIX
if(pdev->device_id == N3_DEVICE)
{
  numvecs = pdev->numvecs = N3_MAX_VECTORS;
  pdev->msix_entries = kmalloc(numvecs * sizeof(struct msix_entry), GFP_KERNEL);
  if(pdev->msix_entries == NULL)
  {
    printk(KERN_CRIT "Failed to allocate msix_entries\n");
    return 1;
  }
  for(i=0; i<numvecs; i++)
     pdev->msix_entries[i].entry = i;
  result = pci_enable_msix((struct pci_dev*)pdev->dev, pdev->msix_entries, numvecs);
  if(result)
  {
   printk(KERN_CRIT "Enabling MSIX failed with %d vectors\n", numvecs);
   if(result > 0)
     printk(KERN_CRIT "Could get only %d vectors\n", result);
   return 1;
  }
  for(i=1; i<numvecs-2; i+=2)
  {
    result = request_irq(pdev->msix_entries[i].vector, linux_layer_isr, IRQF_SHARED, DEVICE_NAME, pdev);
    if(result)
    {
       printk(KERN_CRIT "Failed to request irq for IQ cluster %d (MSIX)\n", (i-1)/2 );
       return 1;
    }
  }
  
  i=17;
  //Error for IQM and general
  result = request_irq(pdev->msix_entries[i].vector, linux_layer_isr, IRQF_SHARED, DEVICE_NAME, pdev);
  if(result)
  {
     printk(KERN_CRIT "Failed to request irq for error_interrupt (MSIX)\n");
     return 1;
  }
  return 0;
}
#endif //MSIX_ENABLED
#endif //CONFIG_PCI_MSI
  if(!n3_vf_driver) {
  interrupt_pin = ((struct pci_dev *)(pdev->dev))->irq;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22))
  result = request_irq(interrupt_pin, linux_layer_isr,SA_SHIRQ,DEVICE_NAME,pdev);
#else
  result = request_irq(interrupt_pin, linux_layer_isr,IRQF_SHARED,DEVICE_NAME,pdev);
#endif
  if(result)
  {
    cavium_print ("pkp_drv: can't get assigned irq : %x\n", interrupt_pin);
    return 1;
  }
  } //!n3_vf_driver
  return 0;
}/* setup interrupt */


/* Let go the interrupt */
void free_interrupt(cavium_device *pdev)
{
  int interrupt_pin = 0;

#ifdef CONFIG_PCI_MSI
#ifdef MSIX_ENABLED
  int i;
  if(pdev->device_id == N3_DEVICE)
  {
    for(i=1; i<pdev->numvecs-2; i+=2)
    {
       free_irq(pdev->msix_entries[i].vector, pdev);
    }
    free_irq(pdev->msix_entries[17].vector, pdev);
    pci_disable_msix((struct pci_dev *)pdev->dev);
    return;
  }
#endif

  if(!n3_vf_driver) {
  interrupt_pin = ((struct pci_dev *)(pdev->dev))->irq;
  free_irq(interrupt_pin, pdev);
  }

  if(pdev->device_id==NPX_DEVICE){
    if(msi_enabled)
      pci_disable_msi((struct pci_dev *)(pdev->dev));
  }   

#endif
}

/* 
 * initialize kernel mode.
 * Calls user interface specific functions.
 */
  int
init_kernel_mode ()
{
  struct N1_Dev *device_node = NULL, *prev = NULL;
  int i;

  MPRINTFLOW();
  for (i = 0; i < dev_count; i++) {
    device_node = cavium_malloc((sizeof(struct N1_Dev)), NULL);
    device_node->next = NULL;
    device_node->id = i;
    device_node->bus = cavium_dev[i].bus_number;
    device_node->dev = cavium_dev[i].dev_number;
    device_node->func = cavium_dev[i].func_number;
    device_node->data = (void *)(&cavium_dev[i]);
    if(device_list == NULL)
      device_list = device_node;
    else
      prev->next = device_node;
    prev = device_node;
  }
#if LINUX_VERSION_CODE < KERNEL_VERSION (2,6,10)
  {
    inter_module_register(N1ConfigDeviceName, THIS_MODULE, 
        n1_config_device);
    inter_module_register(N1UnconfigDeviceName, THIS_MODULE, 
        n1_unconfig_device); 
    inter_module_register(N1AllocContextName, THIS_MODULE, 
        n1_alloc_context);
    inter_module_register(N1FreeContextName, THIS_MODULE, 
        n1_free_context);
    inter_module_register(N1ProcessInboundPacketName, THIS_MODULE,
        n1_process_inbound_packet);
    inter_module_register(N1ProcessOutboundPacketName, THIS_MODULE,
        n1_process_outbound_packet);
    inter_module_register(N1WriteIpSecSaName, THIS_MODULE,
        n1_write_ipsec_sa);
  }
#endif

  return 0;
}/* init_kernel_mode */

/*
 * free kernel mode.
 * Calls user interface specific functions
 */
  int
free_kernel_mode (void)
{
  struct N1_Dev *node = device_list;
  /* 
   * */
  while (node != NULL) {
    struct N1_Dev *tmp;
    tmp = node->next;
    cavium_free(node);
    node = tmp;
  }

#if LINUX_VERSION_CODE < KERNEL_VERSION (2,6,10)
  if (nplus || ipsec>=0)
  {
    inter_module_unregister(N1ConfigDeviceName);
    inter_module_unregister(N1UnconfigDeviceName);
    inter_module_unregister(N1AllocContextName);
    inter_module_unregister(N1FreeContextName);
    inter_module_unregister(N1ProcessInboundPacketName);
    inter_module_unregister(N1ProcessOutboundPacketName);
    inter_module_unregister(N1WriteIpSecSaName);
  }
#endif

  return 0;
}


static int __init cavium_driver_init(void)
{
  int ret_val = 0;
  int cpu;
  int i=0;
#if defined(CAVIUM_DEBUG_LEVEL)
   cavium_debug_level = CAVIUM_DEBUG_LEVEL;
#else
   cavium_debug_level = 0;
#endif
  if(px_only)
     vf_count=0;
  if(vf_count%8)
        vf_count=0;
  printk(KERN_CRIT "VFCOUNT %d\n",vf_count);
/* nplus check */
   if (ssl > 0 && ipsec > 0) {
      cavium_dbgprint("***** PLUS Driver selected *****\n");
      nplus=1;
   }
   else if ((ssl < 0 && ipsec < 0) || (ssl==0 && ipsec==0))
   {
      printk ("Wrong args: It requires ssl=<cores> and/or ipsec=<cores> as arguments\n");
      printk ("    If you want use all available cores for a protocol, say ssl/ipsec=0\n");
      return -ERANGE;
   }
   if (!nplus) {
      cavium_dbgprint("***** NON-PLUS Driver selected *****\n");
   }
/* nplus check done */
  if ((ret_val = pci_register_driver(&cavium_pci_driver))) {
     cavium_error ("Unable to register the cavium driver\n");
     return ret_val;
  }

  ret_val = initmodule();  
   
/*WORKER THREADS */
  get_online_cpus();
  for_each_online_cpu(cpu){
  INIT_DELAYED_WORK(&(work[i]), work_queue_handler); 
#if LINUX_VERSION_CODE <= KERNEL_VERSION (2,6,39)
  work_queue[i]=__create_workqueue("work_threads",1,1,0);
  //work_queue[i]=__create_workqueue("work_threads",1,0,0);
#else
  work_queue[i]= create_singlethread_workqueue("threads");
#endif


  if(work_queue[i] == NULL){
      printk("work queue pointer is NULL\n");
      return 1;
   }
   ret_val = queue_delayed_work_on(i, work_queue[i], &(work[i]), 10);
   i++;
  }
  nr_cpus=i;
  put_online_cpus();
  return 0;
}


static void __exit cavium_driver_exit(void)
{
// put_buffer_in_pool(microcode->code,microcode->code_size);
  int i;
   for(i=0;i<32;i++){
     if(work_queue[i]){
       cancel_delayed_work_sync(&(work[i]));
       destroy_workqueue(work_queue[i]); 
       work_queue[i]=NULL;
    }
   }
  cleanupmodule();
  pci_unregister_driver(&cavium_pci_driver);
  cavium_print("General cleanup \n");
  cavium_general_cleanup();

  cavium_print("Freeing proc resources \n");
  cavium_free_proc();

#if CAVIUM_DEBUG_LEVEL
  printk("UnLoaded Cavium Nitrox Driver --- %01d.%02d-%c\n",
      cavium_version[0],cavium_version[1],cavium_version[2]);
#endif
}/* free_kernel_mode */

int n3_device_count(void)
{
	return dev_count;
}
EXPORT_SYMBOL(n3_device_count);

void 
register_with_px_driver(void **ndev_ptr, void **osd_dev_ptr, uint8_t **base_addr, int device)
{
	*ndev_ptr = &cavium_dev[device];
	*osd_dev_ptr = cavium_dev[device].dev;
	*base_addr = cavium_dev[device].csrbase_a;
	return;
}
EXPORT_SYMBOL(register_with_px_driver);
#if LINUX_VERSION_CODE > KERNEL_VERSION (2,6,10)
EXPORT_SYMBOL(n1_config_device);
EXPORT_SYMBOL(n1_unconfig_device); 
EXPORT_SYMBOL(n1_alloc_context);
EXPORT_SYMBOL(n1_free_context);
EXPORT_SYMBOL(n1_process_inbound_packet);
EXPORT_SYMBOL(n1_process_outbound_packet);
EXPORT_SYMBOL(n1_write_ipsec_sa);
EXPORT_SYMBOL(do_request);
#ifdef PER_PKT_IV
EXPORT_SYMBOL(n1_get_randomIV);
#endif

#ifdef MC2
EXPORT_SYMBOL(n1_invalidate_ipsec_sa);
EXPORT_SYMBOL(n1_flush_packet_queue);
#endif
//#endif
#endif

module_init (cavium_driver_init);
module_exit (cavium_driver_exit);
/*
 * $Id: linux_main.c,v 1.67 2011/04/28 11:43:15 sgadam Exp $
 */
