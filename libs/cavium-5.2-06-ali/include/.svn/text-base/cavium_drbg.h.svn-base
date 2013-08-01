
/* cavium_drbg.h */
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
 * 3. All advertising materials mentioning features or use of this software 
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
#ifndef __CAVIUM_DRBG_H
#define __CAVIUM_DRBG_H

#define DRBG_CLEN		112
#define DRBG_VLEN		112
#define DRBG_CONTROL_LEN	8
#define DRBG_SHA_LEN		64
#define DRBG_NONCE_LEN		16
#define DRBG_FSK_ADDR_LEN        8
#define DRBG_RESEED_LEN          8
#define DRBG_RESEED_VAL	100

typedef struct drbg_data {

	/* Reseed Counter used to calculate the key, also
 	 * decides when to reseed the random number
 	 */
	Uint64 reseed_cntr;

	/* Store the generated key here if NULL fsk_addr*/
	Uint8	key[(DRBG_VLEN + DRBG_CLEN)];
} drbg_data_t;

typedef struct drbg_ctx {

	/* Reseed Counter used to calculate the key, also
 	 * decides when to reseed the random number
 	 */
	Uint64 reseed_cntr;

	union {
		/* Store the generated key here if NULL fsk_addr*/
		Uint8 key[DRBG_VLEN + DRBG_CLEN];

		struct{
			/* User application wants to store the keys in
		 	 * FSK memory then fill the valid address, otherwise
		 	 * makesure this should be zero
		 	 */
			Uint8 is_valid_fsk;
			Uint8 *fsk_addr;
			Uint8 rsvd[215];
		}s;
	}ui;
} drbg_ctx_t;

int Hash_drbg_instantiate(n1_request_type req_type, Uint8 *sha, Uint8 *control, 
  			  Uint8 *res, int res_len, Uint8 *entropy,
			  int entropy_len, Uint8 *nonce, Uint8 *per_str, 
			  int str_len, Uint32 *req_id, Uint32 dev_id);

int Hash_drbg_generate(n1_request_type req_type, Uint8 *sha, Uint8 *control,
                   Uint8  *res, int res_len, Uint8 *reseed, Uint8 *fsk, 
		   Uint8 *additional, int additional_len, Uint8 *key, 
		   int key_len, Uint32 *req_id, int dev_id);

int Hash_drbg_reseed(n1_request_type req_type, Uint8 *sha,Uint8 *control,
                     Uint8 *entropy, int entropy_len, Uint8 *per_str, 
		     int str_len, Uint8 *key, int key_len, Uint8 *fsk,
                     Uint32 *req_id, int dev_id);
#endif /* __CAVIUM_DRBG_H */
