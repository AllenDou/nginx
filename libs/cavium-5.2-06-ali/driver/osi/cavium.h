/* cavium.h  */ 
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

#ifndef _CAVIUM_H_
#define _CAVIUM_H_

#include "cavium_sysdep.h"
#include "cavium_endian.h"
#include "cavium_list.h"
#define INTERRUPT_ON_COMP
#define INTERRUPT_COALESCING
#include "reg-defines-px.h"
#include "reg-defines-n3.h"

/****************************************************************************/
/* Software specific macros                                       */
/****************************************************************************/

#define MAX_CORES_NITROX  56
#define N3_MAX_VECTORS 19 //number of interrupts (crypto+zip+errors)
   
#define COMMAND_BLOCK_SIZE      32
#define COMPLETION_CODE_INIT      (Uint64)0xFFFFFFFFFFFFFFFFULL
#define COMPLETION_CODE_SIZE      8

#ifdef MC2

#if CAVIUM_ENDIAN == __CAVIUM_LITTLE_ENDIAN
#define COMPLETION_CODE_SHIFT      0
#else
#define COMPLETION_CODE_SHIFT      56
#endif

#define SCRATCHPAD_SIZE         4096
#define MAX_PENDING_QUEUE_SIZE  2000
#else /* MC1 */
#if CAVIUM_ENDIAN == __CAVIUM_LITTLE_ENDIAN
#define COMPLETION_CODE_SHIFT      56
#else
#define COMPLETION_CODE_SHIFT      0
#endif

#endif

#define CONTEXT_OFFSET         4194304


#define CAVIUM_DEFAULT_TIMEOUT		(15*CAVIUM_HZ) /* 4 seconds*/
	/* This should be greater than the Microcode's timeout */
/* SRQ Timeout is (MAX_SRQ_TIMEOUT + 1)*CAVIUM_DEFAULT_TIMEOUT*/

#define DOOR_BELL_THRESHOLD      1


/* FSK memory */
#define FSK_BASE             48   
#define NPX_FSK_MAX         (8192 - FSK_BASE) //8K-48 bytes used by mcode
#define N3_FSK_MAX          (32768 - FSK_BASE) //32K-48 bytes used by mcode
#define FSK_CHUNK_SIZE      (2*640)      

/* Extended Key memory stuff */
#define EX_KEYMEM_BASE   DRAM_BASE
#define EX_KEYMEM_MAX   CONTEXT_OFFSET
#define EX_KEYMEM_CHUNK_SIZE   1024   

/* Host Key memory */
#define HOST_KEYMEM_MAX     (512*1024)
#define HOST_KEYMEM_CHUNK_SIZE (2*640)



#define SWAP_SHORTS_IN_64(val)               \
   ((val & (Uint64)0xff00000000000000ULL) >> 8)      \
         |                     \
   ((val & (Uint64)0x00ff000000000000ULL) << 8)      \
         |                     \
   ((val & (Uint64)0x0000ff0000000000ULL) >> 8)      \
         |                     \
   ((val & (Uint64)0x000000ff00000000ULL) << 8)      \
         |                     \
   ((val & (Uint64)0x00000000ff000000ULL) >> 8)      \
         |                     \
   ((val & (Uint64)0x0000000000ff0000ULL) << 8)      \
         |                     \
   ((val & (Uint64)0x000000000000ff00ULL) >> 8)      \
         |                     \
   ((val & (Uint64)0x00000000000000ffULL) << 8)      \

#define SPLIT_TRANSACTION_MASK            0x00700000

extern struct tasklet_struct timer_tasklet[8];
void cavium_timer_tasklet(unsigned long data);
/* 
 * error codes used in handling error interrupts
 */
typedef enum
{
 /* hard reset group ( the tough guys )*/
 ERR_PCI_MASTER_ABORT_WRITE=2,
 ERR_PCI_TARGET_ABORT_WRITE,
 ERR_PCI_MASTER_RETRY_TIMEOUT_WRITE,
 ERR_OUTBOUND_FIFO_CMD,
 ERR_KEY_MEMORY_PARITY,

 /*soft reset group */
 ERR_PCI_MASTER_ABORT_REQ_READ,
 ERR_PCI_TARGET_ABORT_REQ_READ,
 ERR_PCI_MASTER_RETRY_TIMEOUT_REQ_READ,
 ERR_PCI_MASTER_DATA_PARITY_REQ_READ,
 ERR_REQ_COUNTER_OVERFLOW,

 /*EXEC reset group */
 ERR_EXEC_REG_FILE_PARITY,
 ERR_EXEC_UCODE_PARITY,

 /*seq number based errors */
 ERR_PCI_MASTER_ABORT_EXEC_READ,
 ERR_PCI_TARGET_ABORT_EXEC_READ,
 ERR_PCI_MASTER_RETRY_TIMOUT_EXEC_READ,
 ERR_PCI_MASTER_DATA_PARITY_EXEC_READ,
 ERR_EXEC_GENERAL,
 ERR_CMC_DOUBLE_BIT,
 ERR_CMC_SINGLE_BIT   
}PKP_ERROR;


typedef enum {huge_pool = 0, large, medium, small, tiny, ex_tiny, os} pool;

#define BUF_POOLS    6

#define ALIGNMENT   8
#define ALIGNMENT_MASK   (~(0x7L))
#define MAX_DEV   4
struct _pkp_device;

typedef struct{
void (*enable_request_unit)(struct _pkp_device * );
void (*disable_request_unit)(struct _pkp_device *);
void (*disable_exec_units_from_mask)(struct _pkp_device *, Uint64 );
void (*disable_all_exec_units)(struct _pkp_device * );
void (*enable_exec_units)(struct _pkp_device * );
void (*enable_exec_units_from_mask)(struct _pkp_device * ,Uint64 );
void (*setup_request_queues)(struct _pkp_device * );
void (*enable_data_swap)(struct _pkp_device * );
Uint32 (*get_exec_units)(struct _pkp_device * );
void   (*enable_rnd_entropy)(struct _pkp_device *);
#ifdef INTERRUPT_RETURN
int
#else
void 
#endif
#ifdef MSIX_ENABLED
(*interrupt_handler)(int irq, void *arg);
#else
(*interrupt_handler)(void *arg);
#endif
int (*load_microcode)(struct _pkp_device * , int );
}drv_functions;

typedef struct {
    void (*cb)(int, void *);
    void *cb_arg;
    void *post_arg;
    volatile Uint64 *completion_addr;
    int free;
    int is_user;
    int done;
} CMD_DATA;
typedef struct{
    CMD_DATA *cmd_queue;
    spinlock_t pending_lock;
    int queue_front;
    int queue_rear;
    int queue_size;
} pending_queue_t;

typedef struct _pkp_device
{
Uint32 device_id;
Uint32 px_flag;
Uint8 *csrbase_a;
Uint8 *csrbase_b;

void *dev; /* Platform specific device. For OSI it is opaque */
int       dram_present;/* flag. 1 = dram is local.0 = dram is implemented at host*/
Uint32    dram_max; /* total dram size.*/
ptrlong   dram_base; /* dram base address */
Uint32    dram_chunk_count;
Uint32    cmc_ctl_val; /* Context memory control register value*/

Uint32 bus_number;
Uint32 dev_number;
Uint32 func_number;
cavium_physaddr bar_px_hw;
Uint8  *bar_px;
cavium_physaddr bar_0;
cavium_physaddr bar_1;
Uint32 bar_len;
unsigned int interrupt_pin;
Uint32 uen;
Uint32 exec_units;
Uint32 boot_core_mask;
int   enable;
Uint32 imr;
cavium_wait_channel cav_poll;

/* command queue */
Uint32 command_queue_max;
Uint8 *command_queue_front[MAX_N3_QUEUES];
Uint8 *command_queue_end[MAX_N3_QUEUES];
Uint8 *command_queue_base[MAX_N3_QUEUES];
cavium_dmaaddr command_queue_bus_addr[MAX_N3_QUEUES];
Uint8 *real_command_queue_base[MAX_N3_QUEUES];
cavium_dmaaddr real_command_queue_bus_addr[MAX_N3_QUEUES];
Uint32 command_queue_size;
cavium_spinlock_t command_queue_lock[MAX_N3_QUEUES];
ptrlong door_addr[MAX_N3_QUEUES];
Uint32 door_bell_count[MAX_N3_QUEUES];
Uint32 door_bell_threshold[MAX_N3_QUEUES];

#ifdef MC2
Uint8 *ctp_base;
/*the following elements hold the bus addresses*/
cavium_dmaaddr ctp_base_busaddr;
Uint8 *scratchpad_base;
cavium_dmaaddr scratchpad_base_busaddr;
Uint64 *error_val;
cavium_dmaaddr error_val_busaddr;
#endif

/* Context memory pool */
volatile Uint32 ipsec_chunk_count;
volatile Uint32 ssl_chunk_count;
volatile Uint32 ctx_ipsec_free_index;
volatile Uint32 ctx_ipsec_put_index;
volatile Uint32 ctx_ssl_free_index;
ptrlong *ctx_free_list;
ptrlong *org_ctx_free_list;
#ifdef DUMP_FAILING_REQUESTS
ptrlong *org_busctx_free_list;
#endif
cavium_spinlock_t ctx_lock;
int ctx_ipsec_count;
int ctx_ssl_count;


/* Key Memory */
cavium_spinlock_t keymem_lock;
struct cavium_list_head keymem_head;

Uint32 fsk_chunk_count;
Uint16 *fsk_free_list;
volatile Uint32 fsk_free_index;

Uint32 ex_keymem_chunk_count;
Uint32 *ex_keymem_free_list;
volatile Uint32 ex_keymem_free_index;

Uint32 host_keymem_count;
Uint32 *host_keymem_free_list;
struct PKP_BUFFER_ADDRESS *host_keymem_static_list;
volatile Uint32 host_keymem_free_index;


/*ptr to completion_dma_free_list*/
void * ptr_comp_dma;

/* poll thread wait channel */
//cavium_wait_channel cav_poll_wait;

struct MICROCODE microcode[MICROCODE_MAX];


/* Cores list */
core_t cores[MAX_CORES_NITROX];
/*Lock for microcode & cores data structures */
cavium_spinlock_t mc_core_lock;
cavium_spinlock_t uenreg_lock;
int initialized;
drv_functions cavfns;
int max_queues;
int max_cores;
int curr_q;
Uint32 CORE_MASK_0;
Uint32 CORE_MASK_1;
Uint32 CORE_MASK_2;
pending_queue_t pending_queue[64];
#ifdef MSIX_ENABLED
struct msix_entry *msix_entries;
int numvecs;
#endif

}cavium_device, *cavium_device_ptr;

struct N1_Dev {
        struct N1_Dev *next;
        int id;
        int bus;
        int dev;
        int func;
        void *data;
};

typedef struct 
{
    cavium_spinlock_t resource_lock;
    cavium_spinlock_t nbl_lock;
    struct cavium_list_head nbl;
    struct cavium_list_head ctx_head;
    struct cavium_list_head key_head;
    int next;
    int pending;
    int pid;
} tracking_list;    

#ifdef CAVIUM_RESOURCE_CHECK
struct CAV_RESOURCES 
{
   cavium_spinlock_t resource_check_lock;
   struct cavium_list_head ctx_head;
   struct cavium_list_head key_head;
};
#endif

#define SCATTER_THOLD 16384 
#define SCATTER_CHUNK 4096 
/*
 * Buffer Address structure
 */
struct PKP_BUFFER_ADDRESS
{
   ptrlong vaddr; /* virtual address */
   cavium_dmaaddr baddr; /* bus address */
   Uint32 size;
};
/*
 * User Info Buffer
 */
typedef struct 
{
   cavium_device *n1_dev;
   struct cavium_list_head list;
   n1_request_buffer *req;
   n1_request_type req_type;
   Uint16 opcode;
   Uint32 dma_mode;
   Uint8 *in_buffer;
   Uint8 *out_buffer;
   Uint8  *dptr;
   Uint32 dlen;
   Uint8 *rptr;
   Uint32 rlen;
   Uint64 dptr_baddr;
   Uint64 rptr_baddr;
   Uint32 in_size;
   Uint32 out_size;
   cavium_pid_t pid;
   Uint32 signo;
   Uint32 outcnt;
   Uint32 glist_cnt;
   Uint32 slist_cnt;
   Uint8   *outptr[MAX_OUTCNT];
   Uint8   *glist_ptr[MAX_OUTCNT];
   Uint32  glist_ptrsize[MAX_OUTCNT];
   Uint32  outsize[MAX_OUTCNT];
   Uint32  outoffset[MAX_OUTCNT];
   Uint32  outunit[MAX_OUTCNT];
   Uint8  *slist_ptr[MAX_INCNT];
   Uint32 slist_ptrsize[MAX_INCNT];
   Uint32 sflag;
   Uint32 gflag;
   cavium_wait_channel channel;
   Uint32 status;
   Uint64 time_in;
   Uint32 request_id;
   Uint16 queue;
   Uint16 index;
   CMD_DATA *cmd_data;
   volatile Uint64 *completion_addr;
} n1_user_info_buffer;
/*
 * Kernel Info Buffer
 */
typedef struct 
{
   cavium_device *n1_dev;
   n1_request_type req_type;
   Uint32 dma_mode;
   Uint16 opcode;
   Uint8  *dptr;
   Uint8 *rptr;
   Uint32 dlen;
   Uint32 rlen;
   Uint64 dptr_baddr;
   Uint64 rptr_baddr;
   Uint64 ctx_ptr;
   Uint64 time_in;
   volatile Uint64 *completion_addr;
/*Scatter Gather related */
   Uint16 incnt;
   Uint16 outcnt;
   struct PKP_BUFFER_ADDRESS inbuffer[MAX_INCNT];
   Uint32   inunit[MAX_INCNT];
   struct PKP_BUFFER_ADDRESS outbuffer[MAX_OUTCNT];
   Uint32   outunit[MAX_OUTCNT];
   Uint16 gather_list_size;
   Uint16 scatter_list_size;
   cavium_dmaaddr sg_dma_baddr;   
   volatile Uint64 *sg_dma;
   volatile Uint64 *sg_dma_orig;
   Uint32 sg_dma_size;
   //volatile Uint64 *completion_dma; 
   struct PKP_BUFFER_ADDRESS completion_dma;
} n1_kernel_info_buffer;



/*
 * Scatter/gather structs
 */

struct PKP_4_SHORTS
{
 Uint16 short_val[4];
};


struct CSP1_SG_LIST_COMPONENT
{
Uint16 length[4];
Uint64 ptr[4];
};


struct CSP1_SG_STRUCT
{
Uint16 unused[2];               /* unused locations */
Uint16 gather_list_size;
Uint16 scatter_list_size;                  
struct CSP1_SG_LIST_COMPONENT   *gather_component;
struct CSP1_SG_LIST_COMPONENT   *scatter_component;
};


struct CSP1_PATCH_WRITE
{
Uint8 prebytes[8];
Uint8 postbytes[8];
};




/*
 * General software functions
 */

#define ring_door_bell(pdev,q,cnt)   write_PKP_register(pdev,(Uint8 *)((pdev)->door_addr[(q)]),(0x80000000|(cnt)))

/*
 * Direct
 */
int pkp_setup_direct_operation(cavium_device *pdev,
      Csp1OperationBuffer *csp1_operation, 
      n1_kernel_info_buffer *pkp_direct_operation);
/*
 * Unmap the bus addresses
 */
void pkp_unsetup_direct_operation(cavium_device *pdev,
      n1_kernel_info_buffer *pkp_direct_operation);

/*
 * Scatter/Gather
 */
int pkp_setup_sg_operation(cavium_device *pdev,
      Csp1OperationBuffer *csp1_operation, 
      n1_kernel_info_buffer *pkp_sg_operation );

void check_endian_swap( n1_kernel_info_buffer *pkp_sg_operation, int rw);

/*
 * Unmap all inpout and output buffers provided by the application
 */
void pkp_unmap_user_buffers(cavium_device *pdev,n1_kernel_info_buffer *pkp_sg_operation);


/*
 * Flushed the contents of all user buffers.
 */
void 
pkp_flush_input_buffers(cavium_device *pdev,n1_kernel_info_buffer *pkp_sg_operation);

void 
pkp_invalidate_output_buffers(cavium_device *pdev,n1_kernel_info_buffer *pkp_sg_operation);

int
check_completion(cavium_device *n1_dev, volatile Uint64 *p, int max_wait_states, int ucode_idx, int srq_idx);

int check_nb_command_id(cavium_device *n1_dev, void *private_data, Uint32 request_id);

Uint32 check_all_nb_command(cavium_device *,void *data, Csp1StatusOperationBuffer *);

void  init_npx_group_list(void);
Uint8 npx_group_is_used(Uint8 core_grp);
Uint8 get_next_npx_group(void);
void  free_npx_group(Uint8  core_grp);

int get_completion_dma(cavium_device *pdev, struct PKP_BUFFER_ADDRESS *buf);
int put_completion_dma(cavium_device *pdev, struct PKP_BUFFER_ADDRESS *buf);
#endif


/*
 * $Id: cavium.h,v 1.37 2010/05/28 09:15:28 aravikumar Exp $
 */
