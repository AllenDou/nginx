// $Id $
// px_req.c
// This program gives the description of first 8 bytes of the Px Macro
// Instruction

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/cavium_le.h"
#include "../include/cavium_common.h"
int main(int argc, char *argv[])
{
   char hexnum[18];
   int i;

   unsigned long long irh;

   if ((argc != 2) && (argc != 9)) {
      printf ("Usage: %s <value>\n   or: %s <byte0><byte1>...<byte7>\n", argv[0], argv[0]);
      exit(0);
   }

   if (argc == 9) {
        for (i=1; i<9; i++) {
	    strncat(hexnum,argv[i],2);
	}
	irh = strtoull(hexnum, NULL, 16);
   }
   else irh = strtoull(argv[1], NULL, 16);
   printf("\n irh = %llx\n",irh);

ENDIAN_SWAP_8_BYTE(irh);
   printf ("\nPx/Nlite/N1 Instruction Format:\n");
   if(((irh >> 63) & 0x1))
     printf ("  Interrupt Upon Completion		: Yes\n");
   else
     printf ("  Interrupt Upon Completion		: No\n");

   
   if(((irh >> 55) & 0x1))
     printf ("  DMA Mode				: Scatter Gather \n");
   else
     printf ("  DMA Mode				: Direct \n");

   if(((irh >> 54) & 0x1))
     printf ("  Plus mode More Requests			: Another request should be processed after completing the current request  \n");

   if(((irh >> 53) & 0x1))
     printf ("  Processing				: Inline \n");

   if(((irh >> 48) & 0x1f) ==  0x01)
   {
     printf ("  MAJ					: MISC \n");
     if(((irh >> 56) & 0x7f) ==  0x00)
       {
         printf ("  Minor			        	: OPCODE_write_epci\n");
         printf ("  Param1				: Unused \n");
         printf ("  Param2				: Unused \n");
         printf ("  dlen [8 + No.of bytes to write]	: %02d \n", (int)((irh) & 0xffff));
       }
     else if(((irh >> 56) & 0x7f) ==  0x01)
       {
         printf ("  Minor					: OPCODE_random\n");
         printf ("  Param1 [Output size in bytes]		: 0x%02x \n", (int)((irh >> 32) & 0xffff));
         printf ("  Param2 [MBZ]				: 0x%02x \n", (int)((irh >> 16) & 0xffff));
         printf ("  dlen   [MBZ]				: %02d \n", (int)((irh) & 0xffff));
       }
     else if(((irh >> 56) & 0x7f) ==  0x02)
       {
         printf ("  Minor                               	: OPCODE_write_context\n");
         printf ("  Param1                              	: Unused \n");
         printf ("  Param2                              	: Unused \n");
         printf ("  dlen   [ROUNDUP8(context size)]     	: %02d \n", (int)((irh) & 0xffff));
       }
     else if(((irh >> 56) & 0x7f) ==  0x03)
       {
         printf ("  Minor					: OPCODE_write_ssl_context\n");
         printf ("  Param1				: Unused\n");
         if(((irh >> 16) & 0x3) ==  0x01)
           printf ("  Param2[1:0] [Hash Type]		: MD5\n");
	 else if(((irh >> 16) & 0x3) ==  0x02)
           printf ("  Param2[1:0] [Hash Type]		: SHA1\n");
	 else
           printf ("  Param2 [1:0] [Hash Type]		: ERROR!!!!!!\n");
         if(((irh >> 18) & 0x1) ==  0x00)
           printf ("  Param2[2] [SSL Version]		: TLS1.0\n");
	 else
	 {
           if(((irh >> 28) & 0x1) ==  0x01)
              printf ("  Param2[2] [SSL Version]		: TLS1.1\n");
           if(((irh >> 29) & 0x1) ==  0x01)
              printf ("  Param2[2] [SSL Version]		: TLS1.2 \n");
            else
	      printf ("  Param2[2] [SSL Version]		: SSL3.0 \n");
	 }
         if(((irh >> 19) & 0xF) ==  8)
           printf ("  Param2[2] [Cipher Type]		: RC4\n");
	 else
           printf ("  Param2[2] [Cipher Type]		: AES or DES\n");
         if(!((((irh) & 0xFFFF) ==  48) || (((irh) & 0xFFFF) ==  64) || (((irh) & 0xFFFF) ==  80)))
           printf ("  dlen					: ERROR!!!!!!!\n");
	 else
           printf ("  dlen				: %02d\n", (int)((irh) & 0xffff));
       }
     else if(((irh >> 56) & 0x7f) ==  0x04)
       {
         printf ("  Minor					: OPCODE_read_context\n");
         printf ("  Param1 [Size of Output in bytes]	: 0x%02x \n", (int)((irh >> 32) & 0xffff));
         printf ("  Param2				: Unused\n");
         printf ("  dlen   [MBZ]			: %02d \n", (int)((irh) & 0xffff));
       }
     else if(((irh >> 56) & 0x7f) ==  0x08)
       {
         printf ("  Minor					: OPCODE_read_epci\n");
         printf ("  Param1 [Size of Output in bytes]    : 0x%02x \n", (int)((irh >> 32) & 0xffff));
         printf ("  Param2                              : Unused\n");
	 if(((irh) & 0x7f) ==  0x08)
           printf ("  dlen					: %02d \n", (int)((irh) & 0xffff));
	 else
           printf ("  dlen                              : ERROR!!!!!!!\n");
       }
     else if(((irh >> 56) & 0x7f) ==  0x09)
       {
	 printf ("  Minor				        : OPCODE_initialize_rc4\n");
         printf ("  Param1[7:0]  [Key size]		: 0x%02x\n", (int)((irh>>32) & 0x0f));
         printf ("  Param1[15:8] [MBZ]			: 0x%02x\n", (int)((irh>>48) & 0xf0));
         printf ("  Param2[MBZ]				: Unused \n");
         printf ("  dlen  [Key size]			: %02d\n", (int)((irh) & 0xffff));

       }
     else if(((irh >> 56) & 0x7f) ==  0x11)
       {
         printf ("  Minor					: OPCODE_read_datapath\n");
         printf ("  Param1 [Datapath register address]	: 0x%02x \n", (int)((irh >> 32) & 0xffff));
         printf ("  Param2				: Unused\n");
         printf ("  dlen [MBZ]				: %02d \n", (int)((irh) & 0xffff));
       }
     else if(((irh >> 56) & 0x7f) ==  0x12)
       {
         printf ("  Minor					: OPCODE_check_endian\n");
         printf ("  Param1 [MBZ]			: 0x%02x \n", (int)((irh >> 32) & 0xffff));
         printf ("  Param2 [MBZ]			: 0x%02x \n", (int)((irh >> 16) & 0xffff));
         printf ("  dlen   [MBZ]			: %02d \n", (int)((irh) & 0xffff));
       }
     else if(((irh >> 56) & 0x7f) ==  0x13)
       {
         printf ("  Minor					: OPCODE_echo_cmd\n");
         printf ("  Param1 [MBZ]			: 0x%02x \n", (int)((irh >> 32) & 0xffff));
         printf ("  Param2 [MBZ]			: 0x%02x \n", (int)((irh >> 16) & 0xffff));
         printf ("  dlen   [Should be < 880]		: %02d \n", (int)((irh) & 0xffff));
       }
     else if(((irh >> 56) & 0x7f) ==  0x14)
       {
         printf ("  Minor					: OPCODE_roll_call\n");
         printf ("  Param1 [MBZ]			: 0x%02x \n", (int)((irh >> 32) & 0xffff));
         printf ("  Param2 [MBZ]			: 0x%02x \n", (int)((irh >> 16) & 0xffff));
	 if(((irh) & 0x7f) ==  0x08)
           printf ("  dlen				: %02d \n", (int)((irh) & 0xffff));
	 else
           printf ("  dlen				: ERROR!!!!!!!\n");
       }
     else
         printf ("  Minor					: BAD Minor OPCODE\n");
   }
   else if((((irh >> 48) & 0x1f) ==  0x04) || (((irh >> 48) & 0x1f) ==  0x02))
   {
     printf ("  MAJ					: MODEXP OR MODEXP_LARGE \n");
     if(((irh >> 56) & 0x7f) ==  0x00)
       {
         printf ("  Minor					: OPCODE_me\n");
         printf ("  Param1  [Modlen in bytes]		: %02d \n", (int)((irh >> 32) & 0xffff));
         printf ("  Param2  [Explen in bytes]		: %02d \n", (int)((irh >> 16) & 0xffff));
         printf ("  dlen    [Modlen+ExpLen+DataLen]	: %02d \n", (int)((irh) & 0xffff));
       }
     else if(((irh >> 56) & 0x7f) ==  0x01)
       {
         printf ("  Minor					: OPCODE_pkcs1v15dec\n");
         printf ("  Param1 [Modlen in bytes]		: %02d \n", (int)((irh >> 32) & 0xffff));
	 if(((irh >> 16) & 0x1) ==  0x00)
           printf ("  Param2[0] [PKCS Type]				: BT1\n");
	 else
           printf ("  Param2[0] [PKCS Type]			: BT2\n");
         printf ("  Param2[15:1] [MBZ]				: 0x%02x \n", (int)((irh >> 16) & 0xfffe));
         printf ("  dlen[Modlen+ExpLen+DataLen[Modlen]]		: %02d \n", (int)((irh) & 0xffff));
       }
     else if(((irh >> 56) & 0x7f) ==  0x02)
       {
         printf ("  Minor					: OPCODE_pkcs1v15deccrt\n");
         printf ("  Param1 [Modlen in bytes]		: %02d \n", (int)((irh >> 32) & 0xffff));
	 if(((irh >> 16) & 0x1) ==  0x00)
           printf ("  Param2[0] [PKCS Type]				: BT1\n");
	 else
           printf ("  Param2[0] [PKCS Type]			: BT2\n");
         printf ("  Param2[15:1] [MBZ]				: 0x%02x \n", (int)((irh >> 16) & 0xfffe));
         printf ("  dlen [2.5 * Modlen+DataLen]		: %02d \n", (int)((irh) & 0xffff));
       }
     else if(((irh >> 56) & 0x7f) ==  0x03)
       {
         printf ("  Minor:					 OPCODE_pkcs1v15enc\n");
         printf ("  Param1 [Modlen in bytes]		: %02d \n", (int)((irh >> 32) & 0xffff));
	 if(((irh >> 16) & 0x1) ==  0x00)
           printf ("  Param2[0] [PKCS Type]			: BT1\n");
	 else
           printf ("  Param2[0] [PKCS Type]			: BT2\n");
         printf ("  Param2[15:1][ExpLen]			: 0x%02x \n", (int)((irh >> 16) & 0xfffe));
         printf ("  dlen [Modlen+ExpLen+DataLen		: %02d \n", (int)((irh) & 0xffff));
       }
     else if(((irh >> 56) & 0x7f) ==  0x04)
       {
         printf ("  Minor					: OPCODE_pkcs1v15enccrt\n");
         printf ("  Param1 [Modlen in bytes]		: %02d \n", (int)((irh >> 32) & 0xffff));
	 if(((irh >> 16) & 0x1) ==  0x00)
           printf ( "  Param2[0] [PKCS Type]			: BT1\n");
	 else
           printf ( "  Param2[0] [PKCS Type]			: BT2\n");
         printf ( "  Param2[15:1] [MBZ]				: 0x%02x \n", (int)((irh >> 16) & 0xfffe));
         printf ( "  dlen [2.5 * Modlen+DataLen]		: %02d \n", (int)((irh) & 0xffff));
       }
     else if(((irh >> 56) & 0x7f) ==  0x05)
       {
         printf ( "  Minor					: OPCODE_dsa_sign\n");
         printf ( "  Param1 [Modlen in bytes]		: %02d \n", (int)((irh >> 32) & 0xffff));
	 if(((irh >> 16) & 0x1) ==  0x00)
           printf ( "  Param2[0]			: No digest 		 \n");
	 else
           printf ( "  Param2[0]			: Digest		 \n");
         printf ( "  Param2[15:1] [MBZ]			: 0x%02x \n", (int)((irh >> 16) & 0xfffe));
         printf ( "  dlen [2* Modlen+ 40 + MessageLen]	: %02d \n", (int)((irh) & 0xffff));
       }
     else if(((irh >> 56) & 0x7f) ==  0x06)
       {
         printf ( "  Minor					: OPCODE_dsa_verify\n");
         printf ( "  Param1 [Modlen in bytes]		: %02d \n", (int)((irh >> 32) & 0xffff));
	 if(((irh >> 16) & 0x1) ==  0x00)
           printf ( "  Param2[0]			: No digest 		 \n");
	 else
           printf ( "  Param2[0]			: Digest		 \n");
         printf ( "  Param2[15:1] [MBZ]			: 0x%02x \n", (int)((irh >> 16) & 0xfffe));
         printf ( "  dlen [3* Modlen+ 60 + MessageLen]	: %02d \n", (int)((irh) & 0xffff));
       }
     else if(((irh >> 56) & 0x7f) ==  0x07)
       {
         printf ( "  Minor					: OPCODE_gen_random_prime_pair\n");
         printf ( "  Param1 [Modlen in bytes]		: %02d \n", (int)((irh >> 32) & 0xffff));
         printf ( "  Param2 [No of Miller-Rabin iters]	: 0x%02x \n", (int)((irh >> 16) & 0xffff));
         printf ( "  dlen  [length of public key bytes]	: %02d \n", (int)((irh) & 0xffff));
       }
     else if(((irh >> 56) & 0x7f) ==  9)
       {
         printf ( "  Minor				: OPCODE_modmul\n");
         printf ( "  Param1 [Modlen in bytes]		: %02d \n", (int)((irh >> 32) & 0xffff));
         printf ( "  Param2 [MplicandLen in bytes]	: %02d \n", (int)((irh >> 16) & 0xffff));
         printf ( "  dlen [ModLen+MplicandLen+MplierLen]: %02d \n", (int)((irh) & 0xffff));
       }
     else if(((irh >> 56) & 0x7f) ==  12)
       {
         printf ( "  Minor					: OPCODE_dh_generate_keypair\n");
         printf ( "  Param1 [PrivateKeyLen in bytes]	: 0x%02x \n", (int)((irh >> 32) & 0xffff));
           printf ( "  Param2[2:0] [DH Group] 		: 0x%02x\n",(int)((irh >> 16) & 0x7));
	 if(((irh >> 16) & 0x3) ==  0x00)
	 {
           printf ( "  Param2[15:3]  [Modlength]	: %02d\n",(int)((irh >> 16) & 0xfff8));
           printf ( "  dlen: [Modlength+GenLength]	: %02d\n",(int)((irh) & 0xffff));
	 }
	 else
	 {
           printf ( "  Param2[15:3] [MBZ]		: 0x%02x\n",(int)((irh >> 16) & 0xfff8));
           printf ( "  dlen [MBZ]			: %02d\n",(int)((irh) & 0xffff));
	 }
       }
     else if(((irh >> 56) & 0x7f) ==  13)
       {
         printf ( "  Minor				: OPCODE_dh_gen_shared_secret\n");
         printf ( "  Param1 [PrivateKeyLen in bytes]	: 0x%02x \n", (int)((irh >> 32) & 0xffff));
           printf ( "  Param2[2:0] [DH Group] 		: 0x%02x\n",(int)((irh >> 16) & 0x7));
	 if(((irh >> 16) & 0x3) ==  0x00)
	 {
           printf ( "  Param2[15:3]  [Modlength]	: %02d\n",(int)((irh >> 16) & 0xfff8));
           printf ( "  dlen:[2*Modlength+PrivateKeyLen]	: %02d\n",(int)((irh) & 0xffff));
	 }
	 else
	 {
           printf ( "  Param2[15:3] [MBZ]		: 0x%02x\n",(int)((irh >> 16) & 0xfff8));
           printf ( "  dlen: [2*Modlength+PrivateKeyLen]: %02d\n",(int)((irh) & 0xffff));
	 }
       }
     else if(((irh >> 56) & 0x7f) ==  0x7f)
       {
         printf ( "  Minor				: OPCODE_acquire_core\n");
         printf ( "  Param1 [MBZ]			: 0x%02x\n", (int)((irh >> 32) & 0xffff));
         printf ( "  Param2 [MBZ]			: 0x%02x\n", (int)((irh >> 16) & 0xffff));
	 if(((irh) & 0x7f) ==  0x08)
           printf ( "  dlen				: %02d \n", (int)((irh) & 0xffff));
	 else
           printf ( "  dlen				: ERROR!!!!!!!\n");
       }
     else
         printf ( "  Minor				: BAD Minor OPCODE\n");
   }
   else if((((irh >> 48) & 0x1f) ==  0x03) || (((irh >> 48) & 0x1f) ==  0x05))
   {
     printf ( "  MAJ					: RSA Server Small/Large \n");
     printf ( "  Minor[4:0] [MBZ]			: 0x%02x \n", (int)((irh >> 56) & 0x1f));
     if((irh >> 61) & 0x1)
       printf ( "  Minor[5]				: RSA Finish \n");
     else
       printf ( "  Minor[5]				: RSA verify \n");
     if((irh >> 62) & 0x1)
       printf ( "  Minor[6]				: encrypted master secret returned \n");
     else
       printf ( "  Minor[6]				: encrypted master secret not returned \n");
     printf ( "  Param1 [Modlen in bytes]		: %02d \n", (int)((irh >> 32) & 0xffff));
     if(((irh >> 16) & 0x3) ==  0x01)
       printf ( "  Param2[1:0] [Hash Type]		: MD5\n");
     else if(((irh >> 16) & 0x3) ==  0x02)
       printf ( "  Param2[1:0] [Hash Type]		: SHA1\n");
     else
       printf ( "  Param2[1:0] [Hash Type]		: ERROR!!!!!!\n");
     if(((irh >> 18) & 0x1) ==  0x00)
       printf ( "  Param2[2] [SSL Version]		: TLS1.0\n");
     else 
     {
       if(((irh >> 28) & 0x1) ==  0x01)
            printf ( "  Param2[2] [SSL Version]		: TLS1.1\n");
       else if(((irh >> 29) & 0x01) == 0x01)
            printf ( "  Param2[2] [SSL Version]		: TLS1.2\n");
	else
            printf ( "  Param2[2] [SSL Version]		: SSL3.0\n");
     }
     if(((irh >> 19) & 0xF) ==  8)
       printf ( "  Param2[6:3] [Cipher Type]		: RC4\n");
     else if(((irh >> 19) & 0xF) ==  9)
       printf ( "  Param2[6:3] [Cipher Type]		: RC4 Export 40\n");
     else if(((irh >> 19) & 0xF) ==  0x0b)
       printf ( "  Param2[6:3] [Cipher Type]		: RC4 export 56\n");
     else if(((irh >> 19) & 0xF) ==  0x0C)
       printf ( "  Param2[6:3] [Cipher Type]		: DES\n");
     else if(((irh >> 19) & 0xF) ==  0x0D)
       printf ( "  Param2[6:3] [Cipher Type]		: DES_export_40\n");
     else if(((irh >> 19) & 0xF) ==  0x0E)
       printf ( "  Param2[6:3] [Cipher Type]		: 3DES\n");
     else if(((irh >> 19) & 0xF) ==  0x0F)
       printf ( "  Param2[6:3] [Cipher Type]		: DES_export_56\n");
     else if(((irh >> 19) & 0xF) ==  0x05)
       printf ( "  Param2[6:3] [Cipher Type]		: AES128\n");
     else if(((irh >> 19) & 0xF) ==  0x07)
       printf ( "  Param2[6:3] [Cipher Type]		: AES256\n");
     else
       printf ( "  Param2[6:3] [Cipher Type]		: ERROR!!!!!!\n");
     if(((irh >> 23) & 0x1) ==  0x01)
       printf ( "  Param2[7]				: Handshake Hash Type \n");
     else
       printf ( "  Param2[7] [Handshake Hash Type]	: ERROR MBS		 \n");
     if((!(((irh >> 19) & 0xF) ==  8)) && ((irh >> 61) & 0x1))
     {
       if(((irh >> 23) & 0x1) ==  0x01)
         printf ( "  Param2[8]				: unencrypted client finished message returned \n");
       else
         printf ( "  Param2[8]				: unencrypted client finished message not returned \n");
       if(((irh >> 24) & 0x1) ==  0x01)
         printf ( "  Param2[9]				: unencrypted server finished message returned \n");
       else
         printf ( "  Param2[9]				: unencrypted server finished message not returned \n");
     }
     else
       printf ( "  Param2[8:9] [MBZ]			: 0x%02x\n", (int)((irh >> 24) & 0x3));
     printf ( "  Param2[15:10] [MBZ]			: 0x%02x \n", (int)((irh >> 26) & 0x3f));
     printf ( "  dlen   [72+Modlength+MessageLength]	: %02d\n",(int)((irh) & 0xFFFF));
   }

   else if(((irh >> 48) & 0x1f) ==  0x06)
   {
     printf ( "  MAJ					: Hash \n");
     if(((irh >> 56) & 0x7f) ==  0x06)
       printf ( "  Minor[6:0]				: Hash Full \n");
     else if(((irh >> 56) & 0x7f) ==  0x02)
       printf ( "  Minor[6:0]				: Hash start \n");
     else if(((irh >> 56) & 0x7f) ==  0x04)
       printf ( "  Minor[6:0]				: Hash finish \n");
     else if(((irh >> 56) & 0x7f) ==  0x00)
       printf ( "  Minor[6:0]				: Hash update \n");
     printf ( "  Param1 [MBZ]				: 0x%02x \n", (int)((irh >> 32) & 0xffff));
     if(((irh >> 16) & 0x7) ==  0x01)
       printf ( "  Param2[2:0] [Hash Type]		: MD5\n");
     else if(((irh >> 16) & 0x3) ==  0x02)
       printf ( "  Param2[2:0] [Hash Type]		: SHA1\n");
     else if(((irh >> 16) & 0x3) ==  0x03)
       printf ( "  Param2[2:0] [Hash Type]		: SHA256\n");
     else if(((irh >> 16) & 0x3) ==  0x04)
       printf ( "  Param2[2:0] [Hash Type]		: SHA384\n");
     else if(((irh >> 16) & 0x3) ==  0x05)
       printf ( "  Param2[2:0] [Hash Type]		: SHA512\n");
     else
       printf ( "  Param2 [2:0] [Hash Type]		: ERROR!!!!!!\n");
     printf ( "  Param2[15:3] [MBZ]			: 0x%02x\n", (int)((irh >> 16) & 0xfff8));
     printf ( "  dlen [MessageLen]			: %02d\n",(int)((irh) & 0xffff));
   }
   else if(((irh >> 48) & 0x1f) ==  0x07)
   {
     printf ( "  MAJ					: Hmac \n");
     if(((irh >> 56) & 0x7f) ==  0x06)
       printf ( "  Minor[6:0]				: Hmac Full \n");
     else if(((irh >> 56) & 0x7f) ==  0x02)
       printf ( "  Minor[6:0]				: Hmac start \n");
     else if(((irh >> 56) & 0x7f) ==  0x04)
       printf ( "  Minor[6:0]				: Hmac finish \n");
     else if(((irh >> 56) & 0x7f) ==  0x00)
       printf ( "  Minor[6:0]				: Hmac update \n");
     printf ( "  Param1 [KeyLen]			: 0x%02x \n", (int)((irh >> 32) & 0xffff));
     if(((irh >> 16) & 0x7) ==  0x01)
       printf ( "  Param2[2:0] [Hash Type]		: MD5\n");
     else if(((irh >> 16) & 0x3) ==  0x02)
       printf ( "  Param2[2:0] [Hash Type]		: SHA1\n");
     else if(((irh >> 16) & 0x3) ==  0x03)
       printf ( "  Param2[2:0] [Hash Type]		: SHA256\n");
     else if(((irh >> 16) & 0x3) ==  0x04)
       printf ( "  Param2[2:0] [Hash Type]		: SHA384\n");
     else if(((irh >> 16) & 0x3) ==  0x05)
       printf ( "  Param2[2:0] [Hash Type]		: SHA512\n");
     else
       printf ( "  Param2 [2:0] [Hash Type]		: ERROR!!!!!!\n");
     printf ( "  Param2[15:3] [MBZ]			: 0x%02x\n", (int)((irh >> 16) & 0xfff8));
     printf ( "  dlen [KeyLen + MessageLen]		: %02d\n",(int)((irh) & 0xffff));
   }
   else if(((irh >> 48) & 0x1f) ==  0x0A)
   {
     printf ( "  MAJ					: Other \n");
     printf ( "  Minor[4:0] [MBZ]			: 0x%02x \n", (int)((irh >> 56) & 0x1f));
     if((irh >> 61) & 0x1)
       printf ( "  Minor[5]				: Other Finish \n");
     else
       printf ( "  Minor[5]				: Other verify \n");
     if((irh >> 62) & 0x1)
       printf ( "  Minor[6]				: encrypted master secret returned \n");
     else
       printf ( "  Minor[6]				: encrypted master secret not returned \n");
     printf ( "  Param1 [PreMasterSecretLen in bytes]	: 0x%02x \n", (int)((irh >> 32) & 0xffff));
     if(((irh >> 16) & 0x3) ==  0x01)
       printf ( "  Param2[1:0] [Hash Type]		: MD5\n");
     else if(((irh >> 16) & 0x3) ==  0x02)
       printf ( "  Param2[1:0] [Hash Type]		: SHA1\n");
     else
       printf ( "  Param2[1:0] [Hash Type]		: ERROR!!!!!!\n");
     if(((irh >> 18) & 0x1) ==  0x00)
       printf ( "  Param2[2] [SSL Version]		: TLS1.0\n");
     else
     {
       if(((irh >> 28) & 0x1) ==  0x01)
             printf ("  Param2[2] [SSL Version]		: TLS1.1\n");
       else if(((irh >> 29) & 0x1) ==  0x01)
             printf ("  Param2[2] [SSL Version]		: TLS1.2 \n");
       else
	     printf ("  Param2[2] [SSL Version]		: SSL3.0 \n");
     }
     if(((irh >> 19) & 0xF) ==  8)
       printf ( "  Param2[6:3] [Cipher Type]		: RC4\n");
     else if(((irh >> 19) & 0xF) ==  9)
       printf ( "  Param2[6:3] [Cipher Type]		: RC4 Export 40\n");
     else if(((irh >> 19) & 0xF) ==  0x0b)
       printf ( "  Param2[6:3] [Cipher Type]		: RC4 export 56\n");
     else if(((irh >> 19) & 0xF) ==  0x0C)
       printf ( "  Param2[6:3] [Cipher Type]		: DES\n");
     else if(((irh >> 19) & 0xF) ==  0x0D)
       printf ( "  Param2[6:3] [Cipher Type]		: DES_export_40\n");
     else if(((irh >> 19) & 0xF) ==  0x0E)
       printf ( "  Param2[6:3] [Cipher Type]		: 3DES\n");
     else if(((irh >> 19) & 0xF) ==  0x0F)
       printf ( "  Param2[6:3] [Cipher Type]		: DES_export_56\n");
     else if(((irh >> 19) & 0xF) ==  0x05)
       printf ( "  Param2[6:3] [Cipher Type]		: AES128\n");
     else if(((irh >> 19) & 0xF) ==  0x07)
       printf ( "  Param2[6:3] [Cipher Type]		: AES256\n");
     else
       printf ( "  Param2[6:3] [Cipher Type]		: ERROR!!!!!!\n");
     if(((irh >> 23) & 0x1) ==  0x01)
       printf ( "  Param2[7]				: Handshake Hash Type \n");
     else
       printf ( "  Param2[7] [Handshake Hash Type]	: ERROR MBS		 \n");
     if((!(((irh >> 19) & 0xF) ==  8)) && ((irh >> 61) & 0x1))
     {
       if(((irh >> 23) & 0x1) ==  0x01)
         printf ( "  Param2[8]				: unencrypted client finished message returned \n");
       else
         printf ( "  Param2[8]				: unencrypted client finished message not returned \n");
       if(((irh >> 24) & 0x1) ==  0x01)
         printf ( "  Param2[9]				: unencrypted server finished message returned \n");
       else
         printf ( "  Param2[9]				: unencrypted server finished message not returned \n");
     }
     else
       printf ( "  Param2[8:9] [MBZ]			: 0x%02x\n", (int)((irh >> 24) & 0x3));
     printf ( "  Param2[15:10] [MBZ]			: 0x%02x \n", (int)((irh >> 26) & 0x3f));
     printf ( "  dlen   [64+MessageLength]		: %02d\n",(int)((irh) & 0xFFFF));

   }
   else if(((irh >> 48) & 0x1f) ==  0x0B)
   {
     printf ( "  MAJ					: Finished Finish \n");
     printf ( "  Minor [MBZ]				: 0x%02x \n", (int)((irh >> 56) & 0xff));
     printf ( "  Param1 [MBZ]				: 0x%02x \n", (int)((irh >> 32) & 0xffff));
     if(((irh >> 16) & 0x3) ==  0x01)
       printf ( "  Param2[1:0] [Hash Type]		: MD5\n");
     else if(((irh >> 16) & 0x3) ==  0x02)
       printf ( "  Param2[1:0] [Hash Type]		: SHA1\n");
     else
       printf ( "  Param2[1:0] [Hash Type]		: ERROR!!!!!!\n");
     if(((irh >> 18) & 0x1) ==  0x00)
       printf ( "  Param2[2] [SSL Version]		: TLS1.0\n");
     else
     {
       if(((irh >> 28) & 0x1) ==  0x01)
             printf ("  Param2[2] [SSL Version]		: TLS1.1\n");
       else if(((irh >> 29) & 0x1) ==  0x01)
             printf ("  Param2[2] [SSL Version]		: TLS1.2 \n");
       else
	     printf ("  Param2[2] [SSL Version]		: SSL3.0 \n");
     }
     if(((irh >> 19) & 0xF) ==  8)
       printf ( "  Param2[6:3] [Cipher Type]		: RC4\n");
     else if(((irh >> 19) & 0xF) ==  9)
       printf ( "  Param2[6:3] [Cipher Type]		: RC4 Export 40\n");
     else if(((irh >> 19) & 0xF) ==  0x0b)
       printf ( "  Param2[6:3] [Cipher Type]		: RC4 export 56\n");
     else if(((irh >> 19) & 0xF) ==  0x0C)
       printf ( "  Param2[6:3] [Cipher Type]		: DES\n");
     else if(((irh >> 19) & 0xF) ==  0x0D)
       printf ( "  Param2[6:3] [Cipher Type]		: DES_export_40\n");
     else if(((irh >> 19) & 0xF) ==  0x0E)
       printf ( "  Param2[6:3] [Cipher Type]		: 3DES\n");
     else if(((irh >> 19) & 0xF) ==  0x0F)
       printf ( "  Param2[6:3] [Cipher Type]		: DES_export_56\n");
     else if(((irh >> 19) & 0xF) ==  0x05)
       printf ( "  Param2[6:3] [Cipher Type]		: AES128\n");
     else if(((irh >> 19) & 0xF) ==  0x07)
       printf ( "  Param2[6:3] [Cipher Type]		: AES256\n");
     else
       printf ( "  Param2[6:3] [Cipher Type]		: ERROR!!!!!!\n");
     if(((irh >> 23) & 0x1) ==  0x01)
       printf ( "  Param2[7]				: Handshake Hash Type \n");
     else
       printf ( "  Param2[7] [Handshake Hash Type]	: ERROR MBS		 \n");
     if((!(((irh >> 19) & 0xF) ==  8)) && ((irh >> 61) & 0x1))
     {
       if(((irh >> 23) & 0x1) ==  0x01)
         printf ( "  Param2[8]				: unencrypted client finished message returned \n");
       else
         printf ( "  Param2[8]				: unencrypted client finished message not returned \n");
       if(((irh >> 24) & 0x1) ==  0x01)
         printf ( "  Param2[9]				: unencrypted server finished message returned \n");
       else
         printf ( "  Param2[9]				: unencrypted server finished message not returned \n");
     }
     else
       printf ( "  Param2[8:9] [MBZ]			: 0x%02x\n", (int)((irh >> 24) & 0x3));
     printf ( "  Param2[15:10] [MBZ]			: 0x%02x \n", (int)((irh >> 26) & 0x3f));

     printf ( "  dlen  [HashDataLength]		: %02d\n",(int)((irh) & 0xFFFF));
   }
   else if(((irh >> 48) & 0x1f) ==  0x0C)
   {
     printf ( "  MAJ					: Resume \n");
     printf ( "  Minor[5:0][MBZ]			: 0x%02x \n", (int)((irh >> 56) & 0x1f));

     if((irh >> 62) & 0x1)
       printf ( "  Minor[6]				: Use encrypted master secret from input \n");
     else
       printf ( "  Minor[6]				: Do not Use encrypted master secret from input \n");
     printf ( "  Param1 [ModLen in bytes]		: 0x%02x \n", (int)((irh >> 32) & 0xffff));
     if(((irh >> 16) & 0x3) ==  0x01)
       printf ( "  Param2[1:0] [Hash Type]		: MD5\n");
     else if(((irh >> 16) & 0x3) ==  0x02)
       printf ( "  Param2[1:0] [Hash Type]		: SHA1\n");
     else
       printf ( "  Param2[1:0] [Hash Type]		: ERROR!!!!!!\n");
     if(((irh >> 18) & 0x1) ==  0x00)
       printf ( "  Param2[2] [SSL Version]		: TLS1.0\n");
     else
     {
       if(((irh >> 28) & 0x1) ==  0x01)
             printf ("  Param2[2] [SSL Version]		: TLS1.1\n");
     else  if(((irh >> 29) & 0x1) ==  0x01)
             printf ("  Param2[2] [SSL Version]		: TLS1.2 \n");
       else
	     printf ("  Param2[2] [SSL Version]		: SSL3.0 \n");
     }
     if(((irh >> 19) & 0xF) ==  8)
       printf ( "  Param2[6:3] [Cipher Type]		: RC4\n");
     else if(((irh >> 19) & 0xF) ==  9)
       printf ( "  Param2[6:3] [Cipher Type]		: RC4 Export 40\n");
     else if(((irh >> 19) & 0xF) ==  0x0b)
       printf ( "  Param2[6:3] [Cipher Type]		: RC4 export 56\n");
     else if(((irh >> 19) & 0xF) ==  0x0C)
       printf ( "  Param2[6:3] [Cipher Type]		: DES\n");
     else if(((irh >> 19) & 0xF) ==  0x0D)
       printf ( "  Param2[6:3] [Cipher Type]		: DES_export_40\n");
     else if(((irh >> 19) & 0xF) ==  0x0E)
       printf ( "  Param2[6:3] [Cipher Type]		: 3DES\n");
     else if(((irh >> 19) & 0xF) ==  0x0F)
       printf ( "  Param2[6:3] [Cipher Type]		: DES_export_56\n");
     else if(((irh >> 19) & 0xF) ==  0x05)
       printf ( "  Param2[6:3] [Cipher Type]		: AES128\n");
     else if(((irh >> 19) & 0xF) ==  0x07)
       printf ( "  Param2[6:3] [Cipher Type]		: AES256\n");
     else
       printf ( "  Param2[6:3] [Cipher Type]		: ERROR!!!!!!\n");
     if(((irh >> 23) & 0x1) ==  0x01)
       printf ( "  Param2[7]				: Handshake Hash Type \n");
     else
       printf ( "  Param2[7] [Handshake Hash Type]	: ERROR MBS		 \n");
     if((!(((irh >> 19) & 0xF) ==  8)) && ((irh >> 61) & 0x1))
     {
       if(((irh >> 23) & 0x1) ==  0x01)
         printf ( "  Param2[8]				: unencrypted client finished message returned \n");
       else
         printf ( "  Param2[8]				: unencrypted client finished message not returned \n");
       if(((irh >> 24) & 0x1) ==  0x01)
         printf ( "  Param2[9]				: unencrypted server finished message returned \n");
       else
         printf ( "  Param2[9]				: unencrypted server finished message not returned \n");
     }
     else
       printf ( "  Param2[8:9] [MBZ]			: 0x%02x\n", (int)((irh >> 24) & 0x3));
     printf ( "  Param2[15:10] [MBZ]			: 0x%02x \n", (int)((irh >> 26) & 0x3f));

     if((irh >> 62) & 0x1)
       printf ( "  dlen [64+ Handshake data Length]	: %02d\n",(int)((irh) & 0xFFFF));
     else
       printf ( "  dlen [112+ Handshake data Length]	: %02d\n",(int)((irh) & 0xFFFF));
   }
   else if(((irh >> 48) & 0x1f) ==  0x0D)
   {
     printf ( "  MAJ					: Record \n");
     printf ( "  Minor[3:0] [MBZ]			: 0x%02x \n", (int)((irh >> 56) & 0xf));
     if(((irh >> 61) & 0x3) == 0)
       printf ( "  Minor[5:4]				: Message Type change_cipher_spec\n");
     else if(((irh >> 61) & 0x3) == 1)
       printf ( "  Minor[5:4]				: Message Type alert\n");
     else if(((irh >> 61) & 0x3) == 2)
       printf ( "  Minor[5:4]				: Message Type handshake\n");
     else
       printf ( "  Minor[5:4]				: Message Type application_data\n");

     printf ( "  Param1 [Input length in bytes]	: %02d \n", (int)((irh >> 32) & 0xffff));
     if(((irh >> 16) & 0x3) ==  0x01)
       printf ( "  Param2[1:0] [Hash Type]		: MD5\n");
     else if(((irh >> 16) & 0x3) ==  0x02)
       printf ( "  Param2[1:0] [Hash Type]		: SHA1\n");
     else
       printf ( "  Param2[1:0] [Hash Type]		: ERROR!!!!!!\n");
     if(((irh >> 18) & 0x1) ==  0x00)
       printf ( "  Param2[2] [SSL Version]		: TLS1.0\n");
     else
     {
       if(((irh >> 28) & 0x1) ==  0x01)
           printf ("  Param2[2] [SSL Version]		: TLS1.1\n");
       else  if(((irh >> 29) & 0x1) ==  0x01)
           printf ("  Param2[2] [SSL Version]		: TLS1.2 \n");
       else
	   printf ("  Param2[2] [SSL Version]		: SSL3.0 \n");
     }
     if(((irh >> 19) & 0xF) ==  8)
       printf ( "  Param2[6:3] [Cipher Type]		: RC4\n");
     else if(((irh >> 19) & 0xF) ==  0x0E)
       printf ( "  Param2[6:3] [Cipher Type]		: 3DES\n");
     else if(((irh >> 19) & 0xF) ==  0x05)
       printf ( "  Param2[6:3] [Cipher Type]		: AES128\n");
     else if(((irh >> 19) & 0xF) ==  0x07)
       printf ( "  Param2[6:3] [Cipher Type]		: AES256\n");
     else
       printf ( "  Param2[6:3] [Cipher Type]		: ERROR!!!!!!\n");
     if(((irh >> 23) & 0x1) ==  0x01)
     {
       printf ( "  Param2[7]				: Record Decrypt		 \n");
       printf ( "  Param2[9:8] [MBZ]			: 0x%02x\n", (int)((irh >> 24) & 0x3));
     }
     else
     {
       printf ( "  Param2[7]				: Record Encrypt		 \n");
       printf ( "  Param2[11:8]	[Pad length]		: %02d\n", (int)((irh >> 24) & 0xf));
     }
     printf ( "  Param2[15:10] [MBZ]			: 0x%02x \n", (int)((irh >> 26) & 0x3f));
     printf ( "  dlen  [Input data Length]		: %02d\n",(int)((irh) & 0xFFFF));
   }
   else if(((irh >> 48) & 0x1f) ==  0x0E)
   {
     printf ( "  MAJ					: Encdec \n");
     if((((irh >> 56) & 0x7f) ==  0x00) || (((irh >> 56) & 0x7f) ==  0x20))
     {
       printf ( "  Minor					: OPCODE_encrypt_rc4\n");
       if(((irh >> 61) & 0x3) == 2)
         printf ( "  Minor[5]				: Update Context\n");
       printf ( "  Param1 [Input size]			: %02d\n", (int)((irh>>32) & 0xffff));
       printf ( "  Param2 [MBZ]				: 0x%02x \n", (int)((irh>>16) & 0xffff));
       printf ( "  dlen					: %02d \n", (int)((irh) & 0xffff));
     }
     else if((((irh >> 56) & 0x7f) ==  0x04) || (((irh >> 56) & 0x7f) ==  0x05))
     {
     
       if(((irh >> 56) & 0x7f) ==  0x04)
         printf ( "  Minor                                	: %llx OPCODE_encrypt_3des\n",((irh >> 56) & 0x7f));
       else
         printf ( "  Minor                                	: %llx OPCODE_decrypt_3des\n",((irh >> 56) & 0x7f));
       if((((irh >> 32)>>15) & 0x1) ==  0x01)
         printf ( "  Param1[15]                         	: %llx = SingleCrypto\n",(((irh >> 32)>>15) & 0x1));
       else
         printf ( "  Param1[15]                         	: %llx = GeneralCrypto\n",(((irh >> 32)>>15) & 0x1));
       if((((irh >> 32)>>12) & 0x7) ==  0x0)
         printf ( "  Param1[14:12]                      	: %llx = Unused(MBZ)\n",(((irh >> 32)>>12) & 0x7));
       if((((irh >> 32)>>8) & 0xf) ==  0x0)
         printf ( "  Param1[11:8]                       	: %llx = Hmac_type NULL\n",(((irh >> 32)>>8) & 0xf));
       else if((((irh >> 32)>>8) & 0xf) ==  0x1)
         printf ( "  Param1[11:8]                      		: %llx = Hmac_type MD5\n",(((irh >> 32)>>8) & 0xf));
       else if((((irh >> 32)>>8) & 0xf) ==  0x2)
         printf ( "  Param1[11:8]                       	: %llx = Hmac_type SHA1\n",(((irh >> 32)>>8) & 0xf));
       if((((irh >> 32)>>7) & 0x1) ==  0x0)
         printf ( "  Param1[7]                          	: %llx = Unused(MBZ)\n",(((irh >> 32)>>7) & 0x1));
       if((((irh >> 32)>>3) & 0xf) ==  0x0)
         printf ( "  Param1[6:3]                        	: %llx = CBC mode \n",(((irh >> 32)>>3) & 0xf));
       else if((((irh >> 32)>>3) & 0xf) ==  0x1)
         printf ( "  Param1[6:3]                        	: %llx = CFB mode \n",(((irh >> 32)>>3) & 0xf));
       else if((((irh >> 32)>>3) & 0xf) ==  0x2)
         printf ( "  Param1[6:3]                        	: %llx = ECB mode \n",(((irh >> 32)>>3) & 0xf));
       printf ( "  Param1[2:0]                          	: %llx = Unused(MBZ) \n",((irh >> 32) & 0x7));

       if((((irh >> 32)>>8) & 0xf) ==  0x0)
        printf ( "  Param2                              	: 0x%llx Unused(MBZ)\n", ((irh >> 16) & 0xffff));
       else
        printf ( "  Param2                              	: %lld Data_length\n", ((irh >> 16) & 0xffff));
       printf ( "  dlen                                 	: %lld \n", ((irh) & 0xffff));
     }
     else if((((irh >> 56) & 0x7f) ==  0x06) || (((irh >> 56) & 0x7f) ==  0x07))
     {
       if(((irh >> 56) & 0x7f) ==  0x06)
         printf ( "  Minor                                	: %llx = OPCODE_encrypt_aes\n",((irh >> 56) & 0x7f));
       else
         printf ( "  Minor                                	: %llx = OPCODE_decrypt_aes\n",((irh >> 56) & 0x7f));
       if((((irh >> 32)>>15) & 0x1) ==  0x01)
         printf ( "  Param1[15]                         	: %llx = SingleCrypto\n",(((irh >> 32)>>15) & 0x1));
       else
         printf ( "  Param1[15]                         	: %llx = GeneralCrypto\n",(((irh >> 32)>>15) & 0x1));
       if((((irh >> 32)>>12) & 0x7) ==  0x0)
         printf ( "  Param1[14:12]                      	: %llx = Unused(MBZ)\n",(((irh >> 32)>>12) & 0x7));
       if((((irh >> 32)>>8) & 0xf) ==  0x0)
         printf ( "  Param1[11:8]                       	: %llx = Hmac_type NULL\n",(((irh >> 32)>>8) & 0xf));
       else if((((irh >> 32)>>8) & 0xf) ==  0x1)
         printf ( "  Param1[11:8]                       	: %llx = Hmac_type MD5\n",(((irh >> 32)>>8) & 0xf));
       else if((((irh >> 32)>>8) & 0xf) ==  0x2)
         printf ( "  Param1[11:8]                       	: %llx = Hmac_type SHA1\n",(((irh >> 32)>>8) & 0xf));
       if((((irh >> 32)>>7) & 0x1) ==  0x0)
         printf ( "  Param1[7]                          	: %llx = Unused(MBZ)\n",(((irh >> 32)>>7) & 0x1));
       if((((irh >> 32)>>3) & 0xf) ==  0x0)
         printf ( "  Param1[6:3]                        	: %llx = CBC mode \n",(((irh >> 32)>>3) & 0xf));
       else if((((irh >> 32)>>3) & 0xf) ==  0x1)
         printf ( "  Param1[6:3]                        	: %llx = CFB mode \n",(((irh >> 32)>>3) & 0xf));
       else if((((irh >> 32)>>3) & 0xf) ==  0x2)
         printf ( "  Param1[6:3]                        	: %llx = ECB mode \n",(((irh >> 32)>>3) & 0xf));
       if(((irh >> 32) & 0x7) ==  0x5)
         printf ( "  Param1[2:0]                        	: %llx = AES128 \n",((irh >> 32) & 0x7));
       else if(((irh >> 32) & 0x7) ==  0x6)
         printf ( "  Param1[2:0]                        	: %llx = AES192 \n",((irh >> 32) & 0x7));
       else if(((irh >> 32) & 0x7) ==  0x7)
         printf ( "  Param1[2:0]                        	: %llx = AES256 \n",((irh >> 32) & 0x7));
       else
         printf ( "  Param1[2:0]                        	: %s = Unused \n",((irh >> 32) & 0x7));
       if((((irh >> 32)>>8) & 0xf) ==  0x0)
        printf ( "  Param2                              	: 0x%llx Unused(MBZ)\n", ((irh >> 16) & 0xffff));
       else
        printf ( "  Param2                              	: 0x%llx Data_length\n", ((irh >> 16) & 0xffff));
       printf ( "  dlen                                 	: %lld \n", ((irh) & 0xffff));
     }
     else if(((irh >> 56) & 0x7f) ==  0x08)
     {
       printf ( "  Minor					: OPCODE_encrypt_aesgcm\n");
       printf ( "  Param1[DataLen w/o IV,KEY,salt,AAD] : %02d \n", (int)((irh >> 32) & 0xffff));
       if(((irh >> 31) & 0x1))
         printf ( "  Param2[15]				: AES_GMAC\n");
       else 
         printf ( "  Param2[15]				: AES_GCM\n");
       printf ( "  Param2[14:3]				: Unused\n");
       if(((irh >> 17) & 0x3) ==  1)
         printf ( "  Param2[2:1]				: keysize 128-bit (10 round)\n");
       else if(((irh >> 17) & 0x3) ==  2)
         printf ( "  Param2[2:1]				: keysize 192-bit (12 round)\n");
       else if(((irh >> 17) & 0x3) ==  3)
         printf ( "  Param2[2:1]				: keysize 256-bit (14 round)\n");
       else
         printf ( "  Param2[2:1]				: keysize Illegal Treated as 64-bit (14 round)\n");
       if(((irh >> 16) & 0x1))
         printf ( "  Param2[0]				: 64-bit sequence number\n");
       else 
         printf ( "  Param2[0]				: 32-bit sequence number\n");
       printf ( "  dlen [DataLen+ IV + KEY+ SALT + AAD]	: %02d \n", (int)((irh) & 0xffff));
     }
     else if(((irh >> 56) & 0x7f) ==  0x09)
     {
       printf ( "  Minor				: OPCODE_decrypt_aesgcm\n");
       
       printf ( "  Param1[DataLen w/o IV,KEY,salt,AAD,ICV]: %02d \n", (int)((irh >> 32) & 0xffff));
       if(((irh >> 31) & 0x1))
         printf ( "  Param2[15]				: AES_GMAC\n");
       else 
         printf ( "  Param2[15]				: AES_GCM\n");
       printf ( "  Param2[14:5]				: Unused\n");

       if(((irh >> 19) & 0x3) ==  0)
         printf ( "  Param2[4:3]			: ICV length 4 bytes\n");
       else if(((irh >> 17) & 0x3) ==  1)
         printf ( "  Param2[4:3]			: ICV length 8 bytes\n");
       else if(((irh >> 17) & 0x3) ==  2)
         printf ( "  Param2[4:3]			: ICV length 12 bytes\n");
       else
         printf ( "  Param2[4:3]			: ICV length 16 bytes\n");

       if(((irh >> 17) & 0x3) ==  1)
         printf ( "  Param2[2:1]			: keysize 128-bit (10 round)\n");
       else if(((irh >> 17) & 0x3) ==  2)
         printf ( "  Param2[2:1]			: keysize 192-bit (12 round)\n");
       else if(((irh >> 17) & 0x3) ==  3)
         printf ( "  Param2[2:1]			: keysize 256-bit (14 round)\n");
       else
         printf ( "  Param2[2:1]			: keysize Illegal Treated as 64-bit (14 round)\n");
       if(((irh >> 16) & 0x1))
         printf ( "  Param2[0]				: 64-bit sequence number\n");
       else 
         printf ( "  Param2[0]				: 32-bit sequence number\n");
       printf ( "  dlen [DataLen+IV+KEY+SALT+AAD+ICV]	: %02d \n", (int)((irh) & 0xffff));
     }
     else
       printf ( "  Minor				: BAD Minor OPCODE\n");
   }
   else if(((irh >> 48) & 0x1f) ==  16)
   {
   printf ( "  MAJ					: IPSEC INBOUND \n");
   if(((irh >> 56) & 0xff) ==  0x00)
    printf ( "  Context Address Select		: Context Address Specified by Cptr\n");
   else if(((irh >> 56) & 0xff) ==  0x01)
    printf ( "  Context Address Select		: Context Address Calculated from SPI \n");
    if((((irh >> 32)>>15) & 0x1) ==  0x01)
     printf ( "  Param1[15]				: Custome header support\n"); 
    if((((irh >> 32)>>14) & 0x1) ==  0x01)
     printf ( "  Param1[14]				: Override Mode \n"); 
    else
     printf ( "  Param1[14]				: RFC Mode \n"); 
    if((((irh >> 32)>>13) & 0x1) ==  0x01)
     printf ( "  Param1[13]				: %llx UDP checksum : No checksu verification \n",(((irh >> 32)>>13) & 0x1)); 
    else
     printf ( "  Param1[13]				: %llx UDP checksum : Verify the Input IPv4 checksum \n",(((irh >> 32)>>13) & 0x1)); 

    printf ( "  Param1[12:0]				: Reserved \n"); 
    printf ( "  Param2					: Unused \n");
    printf ( "  dlen [IP Packet Size]			: %lld \n", ((irh) & 0xffff));
   }
   else if(((irh >> 48) & 0x1f) ==  17)
   {
    printf ( "  MAJ					: IPSEC OUTBOUND \n");
    if((((irh >> 32)>>15) & 0x1) ==  0x01)
     printf ( "  Param1[15]				: Custome header support\n"); 
    if((((irh >> 32)>>14) & 0x1) ==  0x01)
     printf ( "  Param1[14]				: Override Mode \n"); 
    else
     printf ( "  Param1[14]				: RFC Mode \n"); 
    if((((irh >> 32)>>13) & 0x1) ==  0x01)
     printf ( "  Param1[13]				: TFC_Dummy_packet \n"); 
    if((((irh >> 32)>>12) & 0x1) ==  0x01)
     printf ( "  Param1[12]				: TFC_Pad_enable \n"); 
    if((((irh >> 32)>>11) & 0x1) ==  0x01)
     printf ( "  Param1[11]				: PER_PACKET_IV \n"); 
    if((((irh >> 32)>>10) & 0x1) ==  0x01)
     printf ( "  Param1[10]				: Minimum_Fragment_Size \n"); 
    printf ( "  Param1[9:4]				: %llx Reserved(MBZ) \n",(((irh >> 32)>>4)&0x3f)); 
    printf ( "  Param1[3:0] [No of Frags]		: 0x%llx\n",((irh >> 32) & 0x0f));
    if((((irh >> 32)>>12) & 0x1) ==  0x01)
     printf ( "  param2				: %lld TFC pad bytes \n",((irh >> 16) & 0xffff));
    else
     printf ( "  param2				: %lld IPCOMP packet size \n",((irh >> 16) & 0xffff));
    printf ( "  dlen [IP Packet Size + 8]		: %lld\n",((irh) & 0xffff));
   }
   else if(((irh >> 48) & 0x1f) ==  20)
   {
   printf ( "  MAJ					: IPSEC MISC \n");
     if(((irh >> 56) & 0x7f) ==  0x40) 
     {
         printf ( "  Minor					: Write Outbound IPSEC SA OPCODE\n");
         printf ( "  Param1				: Unused \n");
         printf ( "  Param2				: Unused \n");
         printf ( "  dlen [Context Size in bytes] 		: %02d \n", (int)((irh) & 0xffff));
     }
     else if(((irh >> 56) & 0x7f) ==  0x20)
     {
         printf ( "  Minor					: Write Inbound IPSEC SA OPCODE\n");
         printf ( "  Param1				: Unused \n");
         printf ( "  Param2				: Unused \n");
         printf ( "  dlen [Context Size in bytes] 		: %02d \n", (int)((irh) & 0xffff));
     }
     else if(((irh >> 56) & 0x7f) ==  0x01)
     {
         printf ( "  Minor					: ERASE Context OPCODE\n");
         printf ( "  Param1 [(CtxSize >> 3)- 1 < 256]	: 0x%02x \n", (int)((irh >> 32) & 0xffff));
         printf ( "  Param2 [MBZ]			: %02x \n", (int)((irh >> 16) & 0xffff));
         printf ( "  dlen [MBZ]					: %02d \n", (int)((irh) & 0xffff));
     }
     else
         printf ( "  Minor				: BAD Minor OPCODE\n");
   }
   else if(((irh >> 48) & 0x1f) ==  0x18)
   {
     printf ( "  MAJ					: SRTP AES CTR \n");
     printf ( "  Param1 [DataLen excludes IV, KEY]	: %02d \n", (int)((irh >> 32) & 0xffff));
     printf ( "  Param2				: 0x%02x MBZ\n", (int)((irh >> 16) & 0xffff));
     printf ( "  dlen [Input data + IV + KEY]			: %02d \n", (int)((irh) & 0xffff));
   }
   else if(((irh >> 48) & 0x1f) ==  0x1e)
   {
     printf ( "  MAJ					: ECC \n");
     if (((irh >> 56) & 0x7) == 0 ) 
       printf ( "  Minor[2:0]				: %llx - ecc_vector_addition \n",((irh >> 56) & 0x7));
     else if (((irh >> 56) & 0x7) == 1 ) 
       printf ( "  Minor[2:0]				: %llx - UnknownPointMultiply \n",((irh >> 56) & 0x7));
     else if (((irh >> 56) & 0x7) == 2 ) 
       printf ( "  Minor[2:0]				: %llx - FixedPointMultiply \n",((irh >> 56) & 0x7));
     else if (((irh >> 56) & 0x7) == 3 ) 
       printf ( "  Minor[2:0]				: %llx - InitContext \n",((irh >> 56) & 0x7));

     if ((((irh >> 56)>>3) & 0x3) == 0 ) 
       printf ( "  Minor[4:3]				: %llx - P256 \n",(((irh >> 56)>>3) & 0x3));
     else if ((((irh >> 56)>>3) & 0x3) == 1 ) 
       printf ( "  Minor[4:3]				: %llx - P384 \n",(((irh >> 56)>>3) & 0x3));
     else if ((((irh >> 56)>>3) & 0x3) == 2 ) 
       printf ( "  Minor[4:3]				: %llx - P521 \n",(((irh >> 56)>>3) & 0x3));
     else if ((((irh >> 56)>>3) & 0x3) == 3 ) 
       printf ( "  Minor[4:3]				: %llx - Unused \n",(((irh >> 56)>>3) & 0x3));

      printf ( "  Minor[7:5]				: %llx - Unused \n",(((irh >> 56)>>5) & 0x7));

     if (((irh >> 56) & 0x7) == 0 ) {
       printf ( "  Param1 [No.of Pts to be added in Ctx]: 0x%llx \n", ((irh >> 32) & 0xffff));
       printf ( "  Param2				: 0x%llx Unused (MBZ)\n", ((irh >> 16) & 0xffff));
       printf ( "  dlen [Primelen (in bytes)]		: %lld \n", ((irh) & 0xffff));
     } else if (((irh >> 56) & 0x7) == 1 ) {
       printf ( "  Param1 [Klen (in bytes)]		: %lld \n", ((irh >> 32) & 0xffff));
       printf ( "  Param2				: 0x%llx Unused (MBZ)\n", ((irh >> 16) & 0xffff));
       printf ( "  dlen [Klen + 3*Primelen]		: %lld \n", ((irh) & 0xffff));
     } else if (((irh >> 56) & 0x7) == 2 ) {
       printf ( "  Param1 [Klen (in bytes)		: %lld \n", ((irh >> 32) & 0xffff));
       printf ( "  Param2				: 0x%llx Unused (MBZ)\n", ((irh >> 16) & 0xffff));
       printf ( "  Param1 [MBZ]				: 0x%llx \n", ((irh >> 32) & 0xffff));
       printf ( "  Param2				: 0x%llx Unused (MBZ)\n", ((irh >> 16) & 0xffff));
       printf ( "  dlen [3*Primelen (in bytes)]		: %lld \n", ((irh) & 0xffff));
     }
   }
   else if(((irh >> 48) & 0x1f) ==  0x7f)
   {
     printf ( "  MAJ					: ACQUIRE CORE \n");
     printf ( "  Param1 [MBZ]				: 0x%02x \n", (int)((irh >> 32) & 0xffff));
     printf ( "  Param2 [MBZ]				: 0x%02x \n", (int)((irh >> 16) & 0xffff));
     if(((irh) & 0x7f) ==  0x08)
       printf ( "  dlen					: %02d \n", (int)((irh) & 0xffff));
     else
       printf ( "  dlen					: ERROR!!!!!!!\n");
   }
   else
     printf ( "  MAJ					: BAD OPCODE !!!!!!! \n");
}


