/* linux_main.h */
/*
 * Copyright (c) 2003-2004 Cavium Networks (support@cavium.com). All rights 
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

#ifndef _LINUX_MAIN_H_
#define _LINUX_MAIN_H_

#define VENDOR_ID			0x177d
#define N1_DEVICE			0x0001
#define N1_LITE_DEVICE			0x0003
#define NPX_DEVICE			0x0010

#define DEVICE_NAME           "pkp_dev"
#define DEVICE_MAJOR			125	/* Major device number requested */
//#endif

/* number of 32 byte structures */
#define CAVIUM_COMMAND_QUEUE_SIZE	2000

//#ifndef PER_PKT_IV
//#define PER_PKT_IV
//#endif


/* number of pending response structures to be pre-allocated. */
#define CAVIUM_PENDING_MAX CAVIUM_COMMAND_QUEUE_SIZE

/* number of DIRECT operation structures to be pre-allocated. */
#define CAVIUM_DIRECT_MAX  CAVIUM_COMMAND_QUEUE_SIZE 

/* number of SG operation structures to be pre-allocated. */
#define CAVIUM_SG_MAX CAVIUM_COMMAND_QUEUE_SIZE

/* number of scatter/gather lists to be pre-allocated. */
#define CAVIUM_SG_DMA_MAX CAVIUM_COMMAND_QUEUE_SIZE

/*context memory to be pre-allocated,
 * if DDR memory is not found.
 * Otherwise actual size is used. */ 
#define CAVIUM_CONTEXT_MAX  (2*1024*1024) 

/* 32k buffers */
//#ifdef SSL
#define HUGE_BUFFER_CHUNKS               100
/*#else
#define HUGE_BUFFER_CHUNKS              1
#endif*/

/* 16k buffers */
//#ifdef SSL
#define LARGE_BUFFER_CHUNKS              100
/*#else
#define LARGE_BUFFER_CHUNKS		1
#endif*/

/* 8k buffers */
//#ifdef SSL
#define MEDIUM_BUFFER_CHUNKS            100
/*#else
#define MEDIUM_BUFFER_CHUNKS		1
#endif*/

/* 4k buffers */
//#ifdef SSL
#define SMALL_BUFFER_CHUNKS             2500
/*#else
#define SMALL_BUFFER_CHUNKS		1
#endif*/

/* 2k buffers */
//#ifdef SSL
#define TINY_BUFFER_CHUNKS              100
/*#else
#define TINY_BUFFER_CHUNKS		1
#endif*/

/* 1k buffers */
#define EX_TINY_BUFFER_CHUNKS           1000

#define N1ConfigDeviceName "N1ConfigDevice"
#define N1UnconfigDeviceName "N1UnconfigDevice"
#define N1AllocContextName "N1AllocContext"
#define N1FreeContextName "N1FreeContext"
#define N1ProcessInboundPacketName "N1ProcessInboundPacket"
#define N1ProcessOutboundPacketName "N1ProcessOutboundPacket"
#define N1WriteIpSecSaName "N1WriteIpSecSa"

#ifdef CAVIUM_NEW_API
void * n1_config_device(Uint32);
#else
void * n1_config_device();
#endif
void n1_unconfig_device(void);
Uint64 n1_alloc_context(void *);
void n1_free_context(void *device, Uint64 ctx);
Uint32 n1_process_outbound_packet(void *device, Uint16 size, Uint16 param, 
		Uint16 dlen, Uint32 * inbuffer, Uint32 *outbuffer, int rlen,
		Uint64 ctx, CallBackFn cb, void *cb_data, int response_order, int req_queue);

Uint32 n1_process_inbound_packet(void *device, Uint16 size, Uint16 param, 
		Uint16 dlen, Uint32 * inbuffer, Uint32 *outbuffer, int rlen,
		Uint64 ctx, CallBackFn cb, void *cb_data, int response_order, 
		int req_queue);
#ifdef MC2
Uint32 n1_write_ipsec_sa(void *device, IpsecProto proto, Version iver, Version over, 
			 IpsecMode mode, Direction dir, EncType cypher, 
			 Uint8 *e_key, AuthType auth, Uint8 *a_key, 
			 Uint8 template[40], Uint32 spi, Uint8 copy_df,
	  	         Uint8 udp_encap, Uint64 ctx, Uint64 next_ctx, 
			 Uint32 *in_buffer, Uint32 *out_buffer, 
			 CallBackFn cb, void *cb_data, int resp_order, 
			 int req_queue);
void n1_flush_packet_queue(void *device);
Uint32
n1_invalidate_ipsec_sa(void *device, Uint64 ctx, Uint32 *in_buffer, Uint32 *out_buffer, CallBackFn cb, void *cb_data, int res_order,int req_queue);

#ifdef PER_PKT_IV
Uint8 n1_get_randomIV(Uint8* iv, int ivlen);
#endif

#else
Uint32 n1_write_ipsec_sa(void *device, IpsecProto proto, Version version, 
			 IpsecMode mode, Direction dir, EncType cypher, 
			 Uint8 *e_key, AuthType auth, Uint8 *a_key, 
			 Uint8 template[40], Uint32 spi, Uint8 copy_df,
	  	         Uint8 udp_encap, Uint64 ctx, Uint32 *in_buffer, 
			 Uint32 *out_buffer, CallBackFn cb, void *cb_data, 
			 int resp_order, int req_queue);
#endif

int init_kernel_mode (void);
int free_kernel_mode (void);
void work_queue_handler(struct work_struct *w);

#endif

/*
 * $Id: linux_main.h,v 1.12 2010/11/02 08:09:57 sarora Exp $
 */
