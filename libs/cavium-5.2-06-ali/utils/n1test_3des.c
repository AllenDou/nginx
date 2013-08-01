/*! file n1test_3des.c*/
/*
 * Copyright (c) 2003-2005, Cavium Networks. All rights reserved.
 *
 * This Software is the property of Cavium Networks. The Software and all
 * accompanying documentation are copyrighted. The Software made available here
 * constitutes the proprietary information of Cavium Networks. You agree to take *
 * reasonable steps to prevent the disclosure, unauthorized use or unauthorized
 * distribution of the Software. You shall use this Software solely with Cavium
 * hardware.
 *
 * Except as expressly permitted in a separate Software License Agreement
 * between You and Cavium Networks, You shall not modify, decompile,
 * disassemble, extract, or otherwise reverse engineer this Software. You shall
 * not make any copy of the Software or its accompanying documentation, except
 * for copying incident to the ordinary and intended use of the Software and
 * the Underlying Program and except for the making of a single archival copy.
 *
 * This Software, including technical data, may be subject to U.S. export
 * control laws, including the U.S. Export Administration Act and its
 * associated regulations, and may be subject to export or import regulations
 * in other countries. You warrant that You will comply strictly in all
 * respects with all such regulations and acknowledge that you have the
 * responsibility to obtain licenses to export, re-export or import the
 * Software.
 *
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS" AND
 * WITH ALL FAULTS AND CAVIUM MAKES NO PROMISES, REPRESENTATIONS OR WARRANTIES,
 * EITHER EXPRESS,IMPLIED, STATUTORY,OR OTHERWISE, WITH RESPECT TO THE SOFTWARE, * INCLUDING ITS CONDITION,ITS CONFORMITY TO ANY REPRESENTATION OR DESCRIPTION,
 * OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM SPECIFICALLY
 * DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE, MERCHANTABILITY,
 * NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE,LACK OF VIRUSES,ACCURACY OR * COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE TO
 * DESCRIPTION. THE ENTIRE RISK ARISING OUT OF USE OR PERFORMANCE OF THE
 * SOFTWARE LIES WITH YOU.
 *
 */



#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cavium_sysdep.h"
#include "cavium_common.h"

#define KB_SIZE   1024
    
int main(void)
{
        unsigned char *Input, *Output, *DecryptedOutput, key[24], iv[24];
        unsigned int ret;
        Uint64 context_handle;
        Uint32 request_id;
	Uint32 i;
        Uint32 dev_count = 0;
	//Uint32 input_size = 1024*KB_SIZE - 128;
        //Uint32 alloc_size = 1024*KB_SIZE - 1;
	Uint32 input_size = 1024 - 128;
        Uint32 alloc_size = 1024 - 1;
	Uint16  dev_mask=0;
	Uint8  test_set=0;
        FILE *in_file;
        HashType ht;
        Uint8 auth_key[64],cav_hmac_enc[64],cav_hmac_dec[64];
        Uint16 auth_key_len = 0;

	in_file = fopen("/tmp/dump","rw+"); 

    if(OpenNitroxDevice(CAVIUM_DIRECT,CAVIUM_DEV_ID))
    {
        printf("3DES_TEST: Failed to open device file\n");
        return -ENODEV;
    }
    if(Csp1GetDevCnt(&dev_count,&dev_mask))
    {
        printf("Unable to retrieve dev_count \n");
        CspShutdown(0);
        return 1;
    }

    printf("3DES_TEST: devices detected %d \n",dev_count);
    if(dev_count == 0)
    {
       return 1;
    }
    
    while(dev_count--)
    {
        if(!(dev_mask&(1<<dev_count)))
            continue;

        printf("3DES_TEST: Starting..  \n");
        if(OpenNitroxDevice(CAVIUM_DIRECT,dev_count)) {
            printf("3DES_TEST: Failed to open device file\n");
            return -ENODEV;
        }

        CspAllocContext(CONTEXT_SSL, &context_handle,dev_count);

	Input = malloc(alloc_size);
	Output = malloc(alloc_size);
	DecryptedOutput = malloc(alloc_size);

	memset(Input, 0, alloc_size);
	memset(Output, 0, alloc_size);
	memset(DecryptedOutput, 0, alloc_size);

        for(i=0;i<24;i++) {
            key[i]=i;
            iv[i] = i+64;
        }

        for(i=0;i<input_size;i++)
            Input[i]=i;

        printf("3DES_TEST: Encrypting data\n");
        ret = CspEncrypt3Des(CAVIUM_BLOCKING,
                            context_handle, 
                            CAVIUM_NO_UPDATE, 
                            input_size, 
                            Input, 
                            Output,
#ifdef MC2
                            &iv[0],
                            key,
#if 0 /* this feature for single crypto hmac */
                            ht,	    /*hmac_type*/
                            auth_key_len, /*hmac_key_len*/
                            auth_key,      /*hmac_key*/
                            cav_hmac_enc,
#endif
#endif
                            &request_id,dev_count);
        if(ret == ERR_OPERATION_NOT_SUPPORTED) {
            printf("3DES_TEST: Operation not supported\n");
            goto test_error;
        }
        if(ret) {
            printf("3DES_TEST: Encrypt Failed, Error Code: 0x%x\n", ret);
            goto test_error;
        }


        printf("3DES_TEST: Decrypting data\n");
        ret = CspDecrypt3Des(CAVIUM_BLOCKING,
                            context_handle, 
                            CAVIUM_NO_UPDATE, 
                            input_size, 
                            Output, 
                            DecryptedOutput,
#ifdef MC2
                            iv,
                            key,
#if 0 /* this feature for single crypto hmac */
                            ht,
                            auth_key_len,
                            auth_key,
                            cav_hmac_enc,
#endif
#endif
                            &request_id,dev_count);
        if(ret) {
            printf("3DES_TEST: Decrypt Failed, Error Code: 0x%x\n", ret);
            goto test_error;
        }
                
        printf("3DES_TEST: Comparing decrypted data with original\n");
        ret = memcmp(Input, DecryptedOutput, input_size);
        if(ret) {
            printf("3DES_TEST: Comparison Failed\n");
            goto test_error;
        }

test_error:
        if(!ret)
            printf("3DES_TEST: Success\n");
        free(Input);
        free(Output);
        free(DecryptedOutput);        

        CspFreeContext(CONTEXT_SSL, context_handle,dev_count);
        CspShutdown(dev_count);
        if (ret == ERR_OPERATION_NOT_SUPPORTED)
           break;
    }
    return 1;
}



