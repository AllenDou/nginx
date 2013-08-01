/*! file n1test_rc4.c*/
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


#define INPUT_SIZE   0x600
   
//extern int OpenNitroxDevice(int,int);


int main(void)
{
   unsigned char *Input, *Output, *DecryptedOutput, key[256];
   unsigned int i, j, k, l, x, z, ret, counter, test_step = 0;
   Uint64 context_handle;
   Uint32 request_id;
   Uint16 dev_mask=0;
   Uint32 device = 0;
   Uint32 dev_count = 0;

   if(OpenNitroxDevice(CAVIUM_DIRECT,CAVIUM_DEV_ID))
   {
      printf("RC4_TEST: Failed to open device file\n");
      return -ENODEV;
   }
   if(Csp1GetDevType(&device))
      return 1;
   if(Csp1GetDevCnt(&dev_count,&dev_mask))
   {
      printf("Unable to retrieve dev_count \n");
      CspShutdown(CAVIUM_DEV_ID);
      return 1;
   }
   CspShutdown(CAVIUM_DEV_ID);

   printf("RC4_TEST: devices detected %d \n",dev_count);
   if(dev_count == 0)
   {
      return 1;
   }

   while(dev_count--)
   {
      if(!(dev_mask&(1<<dev_count)))
         continue;         

      if(OpenNitroxDevice(CAVIUM_DIRECT,dev_count)) {
         printf("RC4_TEST: Cannot open device file\n");
         return -ENODEV;
      }

      printf("RC4_TEST: Starting...\n");

      CspAllocContext(CONTEXT_SSL, &context_handle,dev_count);

      Input = malloc(0xFFFF);
      if(Input == NULL) return -ENOMEM;
      Output = malloc(0xFFFF);
      if(Output == NULL) return -ENOMEM;
      DecryptedOutput = malloc(0xFFFF);
      if(DecryptedOutput == NULL) return -ENOMEM;

      memset(Input, 0, 0xFFFF);
      memset(Output, 0, 0xFFFF);
      memset(DecryptedOutput, 0, 0xFFFF);

      z = 0;
      j = k = 2;

      for (i = INPUT_SIZE, test_step = 0 ; i < INPUT_SIZE + 1; ) {
         
         for (z =0; z < 1; z++) {

            if (z == 0) {
               l = i % 0xFF;
               memset(Input, l, i);
               memset(key, l, 256);
            } else if(z == 1) {
               for(x = 0; x < i; ) {
                  Input[x++] = 0x00;
                  Input[x++] = l;
               }
               
               for(x = 0; x < 256; ) {
                  key[x++] = 0x00;
                  key[x++] = l;
               }
            } else {
               for(x = 0; x < i; ) {
                  Input[x++] = 0x00;
                  Input[x++] = 0x01;
               }
               
               for(x = 0; x < 256; ) {
                  key[x++] = 0x00;
                  key[x++] = 0x01;
               }
            }
      
            test_step++;  /* Step 1 */
            ret = CspInitializeRc4(CAVIUM_BLOCKING,
                                    context_handle, 
                                    256, 
                                    key,
                                    &request_id,dev_count);
            if(ret) goto test_error;

            for(counter = 0; counter < i; counter++) 
               Input[counter] = counter;

            test_step++;  /* Step 2 */
            printf("RC4_TEST: Calling EncryptRC4 with Original Data (Input Size: %d)\n", i);
            ret = CspEncryptRc4(CAVIUM_BLOCKING,
                                 context_handle, 
                                 CAVIUM_NO_UPDATE, 
                                 i, 
                                 Input, 
                                 Output,
                                 &request_id,dev_count);
            if(ret) goto test_error;

            test_step++;  /* Step 3 */
            ret = CspInitializeRc4(CAVIUM_BLOCKING,
                                    context_handle, 
                                    256, 
                                    key,
                                    &request_id,dev_count);
            if(ret) goto test_error;

            test_step++;  /* Step 4 */
            printf("RC4_TEST: Calling EncryptRC4 with encrypted Data\n");
            ret = CspEncryptRc4(CAVIUM_BLOCKING,
                                 context_handle, 
                                 CAVIUM_NO_UPDATE, 
                                 i, 
                                 Output,
                                 DecryptedOutput,
                                 &request_id,dev_count);
            if(ret) goto test_error;
            
            test_step++;  /* Step 5 */
            printf("RC4_TEST: Comparing decrypted output with Original data\n");
            ret = memcmp(Input, DecryptedOutput, i);
            if(ret) goto test_error;

         }
         j = k;
         if(!i)
            k = 1;
         else
            k = i;
         i = j + k;
      }

test_error:
      if(ret==0) 
         printf("SUCCESS\n");
      else if(ret == ERR_OPERATION_NOT_SUPPORTED) {
	    printf ("RC4_TEST: Operation not supported\n");
      }
      else
         switch(test_step) {
            case 1:   
               printf("RC4_TEST: Failed in 1st instance of initializerc4\n");
               break;
            case 2:
               printf("RC4_TEST: Failed in encryptrc4 of original data\n");
               break;
            case 3:
               printf("RC4_TEST: Failed in 2nd instance of initializerc4\n");
               break;
            case 4:
               printf("RC4_TEST: Failed in encryptrc4 of encrypted data\n");
               break;
            case 5:
               printf("RC4_TEST: Comparison of Original data with decrypted data failed \n");
               printf("length %d\n ", i);
               break;
            default:
               printf("Unknown state\n");
         }

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



