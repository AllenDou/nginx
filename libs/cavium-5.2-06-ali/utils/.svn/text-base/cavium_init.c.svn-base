/* cavium_init.c */
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
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include "cavium_sysdep.h"
#include "cavium_common.h"
#include "cavium_ioctl.h"

int CSP1_driver_handle = -1;

#define VERSION_LEN 	32
#define SRAM_ADDRESS_LEN 	8

/* 
 * cavium_init f1 f2 f2 f4 fn
 */

int main (int argc, char** argv)
{
	Csp1InitBuffer init;
	Csp1DevMask buf;
	int size, cnt;
	int fd;
	int i;
	char version[VERSION_LEN+1];
	char sram_address[SRAM_ADDRESS_LEN+1];
        int dev_count =0;
        char name[30];
	Uint32 device;
	int ret=-1;
		
	if (CSP1_driver_handle < 0)
	{
		CSP1_driver_handle = open("/dev/pkp_dev", 0);
			if (CSP1_driver_handle < 0) 
				{
					printf("CSP1: can't open device pkp_dev\n");
					exit(-1);
				}
	}

	
	if(ioctl(CSP1_driver_handle,IOCTL_N1_GET_DEV_CNT,&buf) == 0)
	{
	  #if CAVIUM_DEBUG_LEVEL>0
           printf("CSP1: Detected devices dev_count %d\n",buf.dev_cnt);
	  #endif
	}
        else
        {
           printf("CSP1: No devices detected \n");
           exit(-1);
        }

	dev_count=buf.dev_cnt;

	memset(&init,0,sizeof(init));	

	for (i=1; i<argc; i++)
	{
		fd = open(argv[i],O_RDONLY,0);
		if (fd < 0)
		{
			printf("CSP1: File %s; Could not open\n",argv[i]);
			perror("error");
			goto init_error;
   		}

		/* version */
		cnt = read(fd,init.version_info[init.size],VERSION_LEN);
		if (cnt != VERSION_LEN)
		{
			printf("CSP1: File %s; Could not read version\n",argv[i]);
			close(fd);

			goto init_error;
		}
		version[VERSION_LEN] = 0;
		memcpy(version,init.version_info[init.size],VERSION_LEN);
	  #if CAVIUM_DEBUG_LEVEL>0
		printf("CSP1: File %s; Version = %32s\n",argv[i],version);
	  #endif

		/* code length */
		cnt = read(fd,&init.code_length[init.size],4);
		if (cnt != 4)
		{
			close(fd);
			printf("CSP1: File %s; Could not read code length\n",argv[i]);
			goto init_error;
		}
		/* keep size consistent in byte lengths */
		init.code_length[init.size] = ntohl(init.code_length[init.size])*4;
		size = init.code_length[init.size];

	#if CAVIUM_DEBUG_LEVEL>0
		printf("CSP1: File %s; Code length = %d\n",argv[i],size);
	#endif
	
		/* data length */
        	cnt = read(fd,&init.data_length[init.size],4);
		if (cnt != 4)
		{
			printf("CSP1: File %s; Could not read data length\n",argv[i]);
			close(fd);

			goto init_error;
		}

        	init.data_length[init.size] = ntohl(init.data_length[init.size]);
		size = init.data_length[init.size];
	
	#if CAVIUM_DEBUG_LEVEL>0
		printf("CSP1: File %s; Data length = %d\n",argv[i],size);
	#endif
	
		/* sram address */
		cnt = read(fd,init.sram_address[init.size],SRAM_ADDRESS_LEN);
		if (cnt != SRAM_ADDRESS_LEN)
		{
			printf("CSP1: File %s; Could not read sram address\n",argv[i]);
			close(fd);

			goto init_error;
		}
		sram_address[SRAM_ADDRESS_LEN] = 0;
		memcpy(sram_address,init.sram_address[init.size],SRAM_ADDRESS_LEN);

	
	#if CAVIUM_DEBUG_LEVEL>0
		printf("CSP1: File %s; SRAM address = %llx\n",argv[i],*(Uint64*)(init.sram_address[init.size]));
	#endif
		
		/* code */
		size = ROUNDUP16(init.code_length[init.size]);
		init.code[init.size] =CAST_TO_X_PTR( malloc(size));
		cnt = read(fd,CAST_FRM_X_PTR(init.code[init.size]),size); 
		if (cnt != size)
		{
			printf("CSP1: File %s; Could not read code\n",argv[i]);
			close(fd);

			goto init_error;
		}


		/* data */
		size = ROUNDUP16(init.data_length[init.size]);
	        init.data[init.size] = CAST_TO_X_PTR(malloc(size));
        	cnt = read(fd,CAST_FRM_X_PTR(init.data[init.size]),size);
		if (cnt != size)
		{
			printf("CSP1: File %s; Could not read data\n",argv[i]);
			close(fd);
			goto init_error;
		}

		/* signature */
		cnt = read(fd,init.signature[init.size],256);
		if (cnt != 256)
		{
			printf("CSP1: File %s; Could not read signature\n",argv[i]);
			close(fd);
			goto init_error;
		}

		init.size++;	

		close(fd);
	}
 
	#if CAVIUM_DEBUG_LEVEL>0
	printf("CSP1: Calling driver IOCTL to load microcode\n");
	#endif

	if(ioctl(CSP1_driver_handle,IOCTL_N1_INIT_CODE,(Uint32*)&init) == 0)
	{
	#if CAVIUM_DEBUG_LEVEL>0
		printf("CSP1: Microcode Load succeeded\n");
	#endif
	}
	else
		printf("CSP1 init failed\n");

        close(CSP1_driver_handle);

        dev_count--;
        cnt=1;
        while(cnt<=dev_count)
        {
           sprintf(name,"%s%d","/dev/pkp_dev",cnt);
           cnt++;

           CSP1_driver_handle = open(name,0);
	   if (CSP1_driver_handle < 0) 
	   {
	      printf("CSP1: can't open device %s\n",name);
	      continue;
	   }
#if CAVIUM_DEBUG_LEVEL >0		
          printf("Opened device %s\n",name);
#endif			 

	   if(ioctl(CSP1_driver_handle,IOCTL_N1_INIT_CODE,(Uint32*)&init) == 0)
		{
           #if CAVIUM_DEBUG_LEVEL > 0		
	              printf("CSP1: Microcode Load succeeded on %s\n",name);
           #endif		
		}	   
	   else
	     	printf("CSP1 init failed on %s\n",name);

           close(CSP1_driver_handle);

   }

init_error:

	for (i=0; i<init.size; i++)
	{
		if (init.code[i])
			free(CAST_FRM_X_PTR(init.code[i]));

		if (init.data[i])
			free(CAST_FRM_X_PTR(init.data[i]));	
	}
 
	if(CSP1_driver_handle != -1)
		close(CSP1_driver_handle);

	return 0;
}

/*
 * $Id: cavium_init.c,v 1.9 2008/08/11 06:16:51 aramesh Exp $
 * $Log: cavium_init.c,v $
 * Revision 1.9  2008/08/11 06:16:51  aramesh
 * added printfs only for CAVIUM_DEBUG_LEVEL >0.
 *
 * Revision 1.8  2008/07/07 12:37:11  aramesh
 * dev_mask is used.
 *
 * Revision 1.7  2008/07/02 12:42:06  aramesh
 * deleted config part and corresponding flags.
 *
 * Revision 1.6  2007/11/21 07:07:33  ksadasivuni
 * all driver load messages now will be printed at CAVIUM_DEBUG_LEVEL>0
 *
 * Revision 1.5  2007/10/16 06:29:25  aramesh
 * --Changes to support NLite/N1 family.
 *
 * Revision 1.4  2007/07/31 10:11:08  tghoriparti
 * N1 related changes done
 *
 * Revision 1.3  2007/07/24 13:00:11  kchunduri
 * --get dev_count from OUTPUT parameter.
 *
 * Revision 1.2  2007/07/04 04:57:07  kchunduri
 * --update to load microcode on all detected nitrox devices.
 *
 * Revision 1.1  2007/02/20 23:43:29  panicker
 * * Utilities checked in
 *
 * Revision 1.5  2006/05/16 09:58:53  kchunduri
 * --changes to support re-aligned API structures.
 *
 * Revision 1.4  2005/09/28 15:54:18  ksadasivuni
 * - Merging FreeBSD 6.0 AMD64 release with CVS Head
 *
 * Revision 1.3  2005/02/01 04:12:33  bimran
 * copyright fix
 *
 * Revision 1.2  2004/05/02 19:46:19  bimran
 * Added Copyright notice.
 *
 * Revision 1.1  2004/04/15 22:40:51  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

