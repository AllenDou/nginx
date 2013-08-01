/* nplus_init.c */
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
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "cavium_sysdep.h"
#include "cavium_common.h"
#include "cavium_ioctl.h"

/*
 *   cavium_init stuff
 */

#define MAX_LEN 50
#define COMMON_PATH "/etc/"
#define MAIN_SSL     "main_ssl2"
#define PLUS_SSL     "plus_sslb"
#define MAIN_IPSEC   "main_ipsec2"
#define PLUS_IPSEC   "plus_ipsec2"
#define BOOT_FILE    "boot_mc2"
#define MAX_CORES_NITROX   56

/* Ucode structure */
char ucode_list[MICROCODE_MAX][MAX_LEN];

struct ucode {
    char *path;
    int ucode_idx;
    Uint32 cores;
};

Uint32 device = 0;

#define VERSION_LEN    32
#define SRAM_ADDRESS_LEN    8

#ifdef CAVIUM_DEBUG
#define   DEBUG_PRINT(x)      printf x
#else
#define   DEBUG_PRINT(x)
#endif

int Csp1_handle = -1;

int ssl_cores =-1;
int ipsec_cores =-1;
char part_num[10];
short ssl=-1, nplus=0,cores=0;

void usage (char *s)
{
   printf ("\nError: Wrong argument list, Usage as follows...\n");
   printf ("\nFor Nplus: \n\t%s[Nitrox Part Number] ssl=<No_of_cores> ipsec=<no_of_cores>\n", s);
   printf ("For Non-Nplus: \n\t%s[Nitrox Part Number] ssl/ipsec=<no_of_cores>\n", s);
   printf ("\t  If no_of_cores not mentioned with protocol it uses all available cores\n");
   printf ("'<No_of_cores>' should not be a negative number\n\n");
}   

/* parse_args: check for nplus or non-nplus patterns along with part_number
 * if it is nplus pattern like: 
 *      ./command [Nitrox Part Number] ssl=<no_of_cores> ipsec=<no_of_cores> 
 * if it is non-nplus pattern like: 
 *      ./command [Nitrox Part Number] ssl/ipsec=<no_of_cores>
 */

int parse_args (int argc, char *argv[])
{
   char *str_indx=0, *str_indx1=0, *argv_ptr;
   int str_len, str_len1, num=-1;
   int cmd_indx=0;

   if (argc > 1) {
      if (!strncmp (argv[1], "CN", 2)) 
      {
         strcpy(part_num,argv[1]);
         if (argc > 2) 
            cmd_indx=2;
      }
      else 
         cmd_indx=1;
   }
   else {
      return -1;
   }
   if (argc == cmd_indx+1) {
      argv_ptr = argv[cmd_indx];
      str_len = strlen(argv_ptr);
/*
      if ((!strncmp(argv_ptr, "ipsec=", 6))||(!strncmp(argv_ptr, "IPSEC=", 6))) 
         ipsec_cores=0;
      else if ((!strncmp(argv_ptr, "ssl=",4))||(!strncmp(argv_ptr, "SSL=",4))) 
         ssl_cores=0;*/
/*      else */ if((str_indx = strchr(argv_ptr, '=')) && 
               (++str_indx < argv_ptr+str_len))
      {   
         if ((!strncmp(argv_ptr,"ssl",3)) || (!strncmp(argv_ptr,"SSL",3))) {
/*            num=atoi(str_indx);
            if (num == 0) return -1;*/
            ssl_cores=atoi(str_indx);
         }
         else if ((!strncmp(argv_ptr,"ipsec",5))||(!strncmp(argv_ptr,"IPSEC",5))) {
/*            num=atoi(str_indx);
            if (num == 0) return -1;*/
            ipsec_cores=atoi(str_indx);
         }
      }
      else 
         return -1;
   }
   else if (argc > cmd_indx+1) {
      str_len = strlen (argv[cmd_indx]);
      str_len1 = strlen (argv[cmd_indx+1]);
      
      if ((!strncmp(argv[cmd_indx], "SSL=", 4) &&
          !strncmp(argv[cmd_indx+1], "IPSEC=", 6)) ||
          (!strncmp(argv[cmd_indx], "ssl=", 4) &&
          !strncmp(argv[cmd_indx+1], "ipsec=", 6)))
      {
         if ((str_indx = strchr(argv[cmd_indx], '=')) &&
             (++str_indx < argv[cmd_indx]+str_len) &&
             (str_indx1 = strchr(argv[cmd_indx+1], '=')) &&
             (++str_indx1 < argv[cmd_indx+1]+str_len1)) 
         {
            num=atoi(str_indx);
            if (num < 1) return -1;
            ssl_cores=num;
            num=atoi(str_indx1);
            if (num < 1) return -1;
            ipsec_cores=num;
            nplus=1;
         }
         else 
            return -1;
      }
      else if ((!strncmp(argv[cmd_indx], "IPSEC=", 6) &&
          !strncmp(argv[cmd_indx+1], "SSL=", 4)) ||
          (!strncmp(argv[cmd_indx], "ipsec=", 6) &&
          !strncmp(argv[cmd_indx+1], "ssl=", 4)))
      {
         if ((str_indx = strchr(argv[cmd_indx], '=')) &&
             (++str_indx < argv[cmd_indx]+str_len) &&
             (str_indx1 = strchr(argv[cmd_indx+1], '=')) &&
             (++str_indx1 < argv[cmd_indx+1]+str_len1))
         {
            num=atoi(str_indx);
            if (num < 0) return -1;
            ipsec_cores=num;
            num=atoi(str_indx1);
            if (num < 0) return -1;
            ssl_cores=num;
            nplus=1;
         }
         else 
            return -1;
      }
      else 
         return -1;
   }
   else 
      return -1;
   return 0;
}

int set_ucode_links ()
{
   uint8_t ulist_indx=0, i;
   for (i = 0; i < MICROCODE_MAX-!nplus; i++) {
      strcpy (ucode_list[i], COMMON_PATH);
   }
   system("rm -f boot.out");
   system("rm -f main_ssl.out");
   system("rm -f main_ipsec.out");
#ifdef MC2
   if(device == N3_DEVICE){
      system("ln -sf " COMMON_PATH "boot_mc2_n3.out boot.out");
      strcat (ucode_list[ulist_indx], BOOT_FILE);
      strcat (ucode_list[ulist_indx], "_n3.out");
      if (nplus) {
         system("ln -sf " COMMON_PATH "main_ssl2_n3.out main_ssl.out");
         strcat (ucode_list[++ulist_indx], MAIN_SSL);
         strcat (ucode_list[ulist_indx], "_n3.out");
         system("ln -sf " COMMON_PATH "main_ipsec2_n3.out main_ipsec.out");
         strcat (ucode_list[++ulist_indx], MAIN_IPSEC);
         strcat (ucode_list[ulist_indx], "_n3.out");
      }
      else if(ssl_cores>-1) {
         system("ln -sf " COMMON_PATH "main_ssl2_n3.out main_ssl.out");
         strcat (ucode_list[++ulist_indx], MAIN_SSL);
         strcat (ucode_list[ulist_indx], "_n3.out");
      }
      else if(ipsec_cores>-1) {
         system("ln -sf " COMMON_PATH "main_ipsec2_n3.out main_ipsec.out");
         strcat (ucode_list[++ulist_indx], MAIN_IPSEC);
         strcat (ucode_list[ulist_indx], "_n3.out");
     }else
         printf ("No-Protocol defined for Nitorx3 Device\n");
   }else if(device == NPX_DEVICE){
      system("ln -sf " COMMON_PATH "boot_mc2_px.out boot.out");
      strcat (ucode_list[ulist_indx], BOOT_FILE);
      strcat (ucode_list[ulist_indx], "_px.out");
      if (nplus) {
         system("ln -sf " COMMON_PATH "main_ssl2_px.out main_ssl.out");
         strcat (ucode_list[++ulist_indx], MAIN_SSL);
         strcat (ucode_list[ulist_indx], "_px.out");
         system("ln -sf " COMMON_PATH "main_ipsec2_px.out main_ipsec.out");
         strcat (ucode_list[++ulist_indx], MAIN_IPSEC);
         strcat (ucode_list[ulist_indx], "_px.out");
      }
      else if(ssl_cores>-1) {
         system("ln -sf " COMMON_PATH "main_ssl2_px.out main_ssl.out");
         strcat (ucode_list[++ulist_indx], MAIN_SSL);
         strcat (ucode_list[ulist_indx], "_px.out");
      }
      else if(ipsec_cores>-1) {
         system("ln -sf " COMMON_PATH "main_ipsec2_px.out main_ipsec.out");
         strcat (ucode_list[++ulist_indx], MAIN_IPSEC);
         strcat (ucode_list[ulist_indx], "_px.out");
      }
      else 
         printf ("No-Protocol defined for Nitorx-Px Device\n");
   }else if(device == N1_DEVICE){
      system("ln -sf " COMMON_PATH "boot_mc2.out boot.out");
      strcat (ucode_list[ulist_indx], BOOT_FILE);
      strcat (ucode_list[ulist_indx], ".out");
      if (nplus) {
         system("ln -sf " COMMON_PATH "plus_sslb_n1.out plus_ssl.out");
         strcat (ucode_list[++ulist_indx], PLUS_SSL);
         strcat (ucode_list[ulist_indx], "_n1.out");
         system("ln -sf " COMMON_PATH "main_ipsec2_n1.out main_ipsec.out");
         strcat (ucode_list[++ulist_indx], MAIN_IPSEC);
         strcat (ucode_list[ulist_indx], "_n1.out");
      }
      else if(ssl_cores>-1) {
         system("ln -sf " COMMON_PATH "main_ssl2_n1.out main_ssl.out");
         strcat (ucode_list[++ulist_indx], MAIN_SSL);
         strcat (ucode_list[ulist_indx], "_n1.out");
      }
      else if(ipsec_cores>-1) {
         system("ln -sf " COMMON_PATH "main_ipsec2_n1.out main_ipsec.out");
         strcat (ucode_list[++ulist_indx], MAIN_IPSEC);
         strcat (ucode_list[ulist_indx], "_n1.out");
      }
      else 
         printf ("No-Protocol defined for N1 Device\n");

  }else if(device == N1_LITE_DEVICE){
      system("ln -sf " COMMON_PATH "boot_mc2.out boot.out");
      strcat (ucode_list[ulist_indx], BOOT_FILE);
      strcat (ucode_list[ulist_indx], ".out");
      if (nplus) {
         system("ln -sf " COMMON_PATH "plus_sslb.out plus_ssl.out");
         strcat (ucode_list[++ulist_indx], PLUS_SSL);
         strcat (ucode_list[ulist_indx], ".out");
         system("ln -sf " COMMON_PATH "main_ipsec2.out main_ipsec.out");
         strcat (ucode_list[++ulist_indx], MAIN_IPSEC);
         strcat (ucode_list[ulist_indx], ".out");
      }
      else if(ssl_cores>-1) {
         system("ln -sf " COMMON_PATH "main_ssl2.out main_ssl.out");
         strcat (ucode_list[++ulist_indx], MAIN_SSL);
         strcat (ucode_list[ulist_indx], ".out");
      }
      else if(ipsec_cores>-1) {
         system("ln -sf " COMMON_PATH "main_ipsec2.out main_ipsec.out");
         strcat (ucode_list[++ulist_indx], MAIN_IPSEC);
         strcat (ucode_list[ulist_indx], ".out");
      }
      else 
         printf ("No-Protocol defined for N-Lite Device\n");
 
   }
   else {
      printf("\n unable to create links for device %d \n",device);
      return -1;
   }
#else 
   printf ("It supports only MC2 microcode\n");
   return -1;
#endif
   return 0;
}

int ucode_dload (int Csp1_handle)
{
   Csp1InitBuffer init;
   int size, cnt;
   int fd;
   int i;
   char version[VERSION_LEN+1];
   char sram_address[SRAM_ADDRESS_LEN+1];
   int ret = 0;
      
   memset(&init,0,sizeof(init));   
   for (i=0; i < MICROCODE_MAX - !nplus; i++)
   {
      fd = open(ucode_list[i], O_RDONLY,0);
      if (fd < 0)
      {
         printf("File %s; Could not open\n",ucode_list[i]);
         perror("error");
         goto init_error;
      }

      /* version */
      cnt = read(fd,init.version_info[init.size],VERSION_LEN);
      if (cnt != VERSION_LEN)
      {
         printf("File %s; Could not read version\n",ucode_list[i]);
         close(fd);

         goto init_error;
      }
      version[VERSION_LEN] = 0;
      memcpy(version,init.version_info[init.size],VERSION_LEN);
      printf("File: %s\n\tVersion = %s\n",ucode_list[i],version);

      /* code length */
      cnt = read(fd,&init.code_length[init.size],4);
      if (cnt != 4)
      {
         close(fd);
         printf("File %s; Could not read code length\n",ucode_list[i]);
         goto init_error;
      }
      /* keep size consistent in byte lengths */
      init.code_length[init.size] = ntohl(init.code_length[init.size])*4;
      size = init.code_length[init.size];
      printf("\tCode length = %d\t",size);
   
      /* data length */
           cnt = read(fd,&init.data_length[init.size],4);
      if (cnt != 4)
      {
         printf("\nFile %s; Could not read data length\n",ucode_list[i]);
         close(fd);

         goto init_error;
      }

      init.data_length[init.size] = ntohl(init.data_length[init.size]);
      size = init.data_length[init.size];
      printf("Data length = %d\n",size);
   
      /* sram address */
      cnt = read(fd,init.sram_address[init.size],SRAM_ADDRESS_LEN);
      if (cnt != SRAM_ADDRESS_LEN)
      {
         printf("File %s; Could not read sram address\n",ucode_list[i]);
         close(fd);

         goto init_error;
      }
      sram_address[SRAM_ADDRESS_LEN] = 0;
      memcpy(sram_address,init.sram_address[init.size],SRAM_ADDRESS_LEN);
      
      /* code */
      size = ROUNDUP16(init.code_length[init.size]);
      init.code[init.size] = CAST_TO_X_PTR(malloc(size));
      cnt = read(fd,CAST_FRM_X_PTR(init.code[init.size]),size); 
      if (cnt != size)
      {
         printf("File %s; Could not read code\n",ucode_list[i]);
         close(fd);

         goto init_error;
      }


      /* data */
      size = ROUNDUP16(init.data_length[init.size]);
           init.data[init.size] = CAST_TO_X_PTR(malloc(size));
           cnt = read(fd,CAST_FRM_X_PTR(init.data[init.size]),size);
      if (cnt != size)
      {
         printf("File %s; Could not read data\n",ucode_list[i]);
         close(fd);
         goto init_error;
      }

      /* signature */
      cnt = read(fd,init.signature[init.size],256);
      if (cnt != 256)
      {
         printf("File %s; Could not read signature\n",ucode_list[i]);
         close(fd);
    ret = -2;
         goto init_error;
      }
//#ifdef NPLUS
      /* ucode_idx */
      init.ucode_idx[init.size] = i; //ucode_array[init.size].ucode_idx;
//#endif
      printf("%d: name=%s, index=%d, core=%d\n", i, ucode_list[i], i, cores); 
      init.size++;   

      close(fd);
   }
   if(ioctl(Csp1_handle,IOCTL_N1_INIT_CODE,(Uint32*)&init)==0) {
      printf ("Microcode Load Succeed\n");
   }else 
      printf ("Microcode Load Failed\n");

init_error:

   for (i=0; i<init.size; i++)
   {
      if (init.code[i])
         free(CAST_FRM_X_PTR(init.code[i]));

      if (init.data[i])
         free(CAST_FRM_X_PTR(init.data[i]));   
   }
   return ret;
}

int check_cores(void)
{
   int s_cores, ip_cores;
    DebugRWReg dw_val;
   int cores =0;
   unsigned long bar_val=0;
   s_cores = (ssl_cores == -1) ? 0: ssl_cores;
   ip_cores = (ipsec_cores == -1) ? 0 : ipsec_cores;
   Uint32 val;
   switch(device)
   {
      case N3_DEVICE:
         if((s_cores+ip_cores)> MAX_CORES_NITROX)
         {
            printf("\n THE MAX NUMBER OF CORES SUPPORTED ARE : %d \n", MAX_CORES_NITROX);
            return 0;
         }
          break;
      case NPX_DEVICE:
          dw_val.addr =0x10; /* Read Bar0 Address */
          if (ioctl(Csp1_handle, IOCTL_PCI_DEBUG_READ_CODE,(Uint32 *) &dw_val)!=0) {
                   printf("Unable to get bar address\n");
                   return(0);
          }
         bar_val = dw_val.data;
   #ifdef LINUX
         if ( bar_val & PCI_BASE_ADDRESS_SPACE_IO )
               bar_val &= PCI_BASE_ADDRESS_IO_MASK;
         else
               bar_val &= PCI_BASE_ADDRESS_MEM_MASK;
   #endif

         dw_val.data=0;
         dw_val.addr =  bar_val+ 0x350; 
         if(ioctl(Csp1_handle, IOCTL_N1_DEBUG_READ_CODE,(Uint32 *)&dw_val)!=0)
         {
           printf("Failed to get number of cores\n");
           exit (1);
         }
          val = (Uint32)dw_val.data&0xff;
         switch(val){
              case 0xff: cores=8;
                         break;
              case 0x3f: cores=6;
                         break;
              case 0x0f: cores=4;
                         break;
              case 0x03: cores=2;
                         break;
        }
         
         if((s_cores+ip_cores)>cores)
         {
            printf("\n THE MAX NUMBER OF CORES SUPPORTED ARE : %d\n",cores);
            return 0;
         }
         break;
      case N1_DEVICE:
         if( ((!strcmp("CN1220",part_num))||(!strcmp("CN1320",part_num))||(!strcmp("CN1120",part_num) )) && (s_cores+ip_cores)>8)
         {
               printf("\n THE MAX NUMBER OF CORES SUPPORTED ARE : 8 \n ");
               return 0;
         }
         else if((s_cores+ip_cores)>16)
         {
                printf("\n THE MAX NUMBER OF CORES SUPPORTED ARE : 16 \n");
                return 0;
         }
         break;   
      case N1_LITE_DEVICE:
         if(( (!strcmp("CN501",part_num)) || (!strcmp("CN1001",part_num)) )  && (s_cores+ip_cores)>1)
         {
            printf("\n THE MAX NUMBER OF CORES SUPPORTED ARE : 1 \n");
            return 0;
         }
         if(( (!strcmp("CN505",part_num)) || (!strcmp("CN1005",part_num)) )  && (s_cores+ip_cores)>2)
         {
            printf("\n THE MAX NUMBER OF CORES SUPPORTED ARE : 2 \n");
            return 0;
         }
         else if((s_cores+ip_cores)>4)
         {
            printf("\n THE MAX NUMBER OF CORES SUPPORTED ARE : 4 \n");
            return 0;
         }
		 break;
      default:
         printf ("Unknown Device: %x\n", device);
         return 0;
   }
   return 1;
}

int init_csp1()
{
   int i, j, k, bit;
   int new_ssl_left=0, new_ipsec_left=0;
   uint8_t old_ssl=0, old_ipsec=0;
   
   if(!check_cores())
   {
	  printf ("ERROR: Cores out of range, Unable to load microcode\n");
      return -1;
   }
   if(ucode_dload(Csp1_handle) != 0)
   {
      printf("ucode_dlaodCSP1 failed to initialize\n");
      return(-1);
   }
/****** set cores for nplus mode *******/   
   if (nplus || ssl_cores>0 || ipsec_cores>0) {
      Csp1CoreAssignment core_assign;
      /* Now check, what cores are available */
      if(ioctl(Csp1_handle, IOCTL_CSP1_GET_CORE_ASSIGNMENT,(Uint32 *)&core_assign) != 0) {
         printf("CSP1 failed to get core assignments\n");
         return(-2);
      }

      //count old_ssl and old_ipsec
      for(i=1; i < MICROCODE_MAX - !nplus; i++)
      {
      	for(j=0; j<MAX_CORES_NITROX; j++)
	{
		if(core_assign.core_mask[BOOT_IDX + i] & (((Uint64)1) << j))
		{
			if(i == 1)
				old_ssl++;
			if(i == 2)
				old_ipsec++;
		}
	}
      }
      new_ssl_left = ssl_cores - old_ssl;      
      new_ipsec_left = ipsec_cores - old_ipsec;

      if(!nplus)
      	goto disable_done;
	
      k = 1; //Microcode index for SSL and IPSec

      //some ssl cores need to be disabled
      if(new_ssl_left < 0)
      {
	for(j=0; j<MAX_CORES_NITROX && (new_ssl_left < 0); j++)
	{
		if(core_assign.core_mask[k] & (((Uint64)1) << j))
		{
			new_ssl_left++;
			core_assign.core_mask[k] &= ~(((Uint64)1) << j);
			core_assign.core_mask[BOOT_IDX] |= (((Uint64)1) << j);
		}
	}
	if(new_ssl_left < 0)
	{
		printf("Invalid migration attempt. Still more SSL cores to disable?\n");
	}
      }
      if (nplus)
	k++; //Index to IPSec Microcode in nplus mode.

      //some ipsec cores need to be disabled
      if(new_ipsec_left < 0)
      {
	for(j=0; j<MAX_CORES_NITROX && (new_ipsec_left < 0); j++)
	{
		if(core_assign.core_mask[k] & (((Uint64)1) << j))
		{
			new_ipsec_left++;
			core_assign.core_mask[k] &= ~(((Uint64)1) << j);
			core_assign.core_mask[BOOT_IDX] |= (((Uint64)1) << j);
		}
	}
	if(new_ipsec_left < 0)
	{
		printf("Invalid migration attempt. Still more IPSEC cores to disable?\n");
	}

      }

disable_done:
//find the first free core
      bit = -1; 
      for(i=0; i<MAX_CORES_NITROX; i++)
      {
         if(core_assign.core_mask[BOOT_IDX] & (((Uint64)1) << i))
	 {
	 	bit = i;
		break;
	 }
      }      
      i = -1;
      k =  1; //SSL Microcode index

      if(bit != -1)
      {
      	//we have some free cores
	if(new_ssl_left > 0)
	{
		for(i=bit; (i<MAX_CORES_NITROX) && (new_ssl_left > 0); i++)
		{
			if(!(core_assign.core_mask[BOOT_IDX] & (((Uint64)1)<<i)))
			{
				//this core isn't free
				continue;
			}
			new_ssl_left--;
			core_assign.core_mask[BOOT_IDX] &= ~(((Uint64)1)<<i);
			core_assign.core_mask[k] |= (((Uint64)1)<<i);
		}
		if(new_ssl_left)
		{
			//we ran out of free cores
			goto ipsec_alloc_done;
		}
		
	}
	if (nplus)
		k++; //IPSec microcode index
	if(new_ipsec_left > 0)
	{
		if(i == -1) 
			i = bit;
		for(; (i<MAX_CORES_NITROX) && (new_ipsec_left > 0); i++)
		{
			if(!(core_assign.core_mask[BOOT_IDX] & (((Uint64)1)<<i)))
			{
				//this core isn't free
				continue;
			}
			new_ipsec_left--;
			core_assign.core_mask[BOOT_IDX] &= ~(((Uint64)1)<<i);
			core_assign.core_mask[k] |= (((Uint64)1)<<i);
		}		
	}
      }
ipsec_alloc_done:
	if(nplus && (new_ssl_left || new_ipsec_left))
	{
		printf("Not possible. Ran out of cores to allocate or disable\n");
		return -3;
	}
     if(ioctl(Csp1_handle, IOCTL_CSP1_SET_CORE_ASSIGNMENT, (Uint32 *)&core_assign) != 0)
      {
         printf("CSP1 failed to set core assignments\n");
         return(-3);
      }
   
      if(ioctl(Csp1_handle, IOCTL_CSP1_GET_CORE_ASSIGNMENT, (Uint32 *)&core_assign) != 0)
      {
          printf("CSP1 failed to get core assignments\n");
          return(-4);
      }
   
      printf("CSP1 core assignments\n");
      for(i=0;i<MICROCODE_MAX-!nplus;i++)
         if(core_assign.mc_present[i])
           printf("%10s : 0x%llx\n",ucode_list[i],(unsigned long long)core_assign.core_mask[i]);

   } /* end nplus */
   return(0);
}

int main(int argc, char *argv[])
{
   Uint32 dev_cnt = 0;
   int i, ret=0;
   Uint16 dev_mask;

   if ((parse_args (argc, argv) < 0) || (ssl_cores < 0 && ipsec_cores < 0)) {
      usage (argv[0]);
      return -1;
   }
   system("rm -f /dev/pkp_dev");   
   system("mknod /dev/pkp_dev c 125 0");

   if(CspInitialize(CAVIUM_DIRECT, CAVIUM_DEV_ID))   
   {   
      printf("failed Initializing device");
      return -1;
   }
   Csp1GetDevCnt(&dev_cnt,&dev_mask);
   switch(dev_cnt)
   {
      case 4:
         system("rm -f /dev/pkp_dev3");   
         system("mknod /dev/pkp_dev3  c 125 3");
      case 3:
         system("rm -f /dev/pkp_dev2");
         system("mknod /dev/pkp_dev2  c 125 2");
      case 2:
         system("rm -f /dev/pkp_dev1");
         system("mknod /dev/pkp_dev1  c 125 1");
      case 1: break;
   }
   for(i=0;i<dev_cnt;i++)
   {
      switch(i)
      {
       case 0:
              Csp1_handle = open("/dev/pkp_dev", 0);
              break;
       case 1:
              Csp1_handle = open("/dev/pkp_dev1", 0);
              break;
       case 2:
              Csp1_handle = open("/dev/pkp_dev2", 0);
              break;
       case 3:
              Csp1_handle = open("/dev/pkp_dev3", 0);
              break;
       default:
               printf("Invalid device count\n");
              exit(0);
      }
      if(Csp1_handle < 0)
      {
        printf("\n the error is %s\n",strerror(errno));
        printf("Error: Unable to open Cavium device file\n");
        printf("Retry after unloading and reloading the driver\n");
        exit(-1);
      }

      if(ioctl(Csp1_handle,IOCTL_N1_GET_DEV_TYPE,&device))
      {
         printf("failed in determining device");
         exit(1);
      }
        
      if (set_ucode_links() < 0) {
         printf ("Error: Unable to set microcode error\n");
         exit(1);
      }

      if(init_csp1()) {
         printf("\nInit Failed\n");
	   ret = -1;
	   goto error;
     }
     if(Csp1_handle >= 0)
     {
       close(Csp1_handle);
     }

    } 
   system("rm -f boot.out");
   system("rm -f main_ssl.out");
   system("rm -f main_ipsec.out");
   exit(0); 
error:
     if(Csp1_handle >= 0)
     {
       close(Csp1_handle);
     }
   exit(1);
}

