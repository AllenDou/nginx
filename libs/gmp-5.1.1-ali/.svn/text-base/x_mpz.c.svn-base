/* x_mpz.c */
/* Copyright (C) 2013 Huang Le
 * All rights reserved.
 *
 * This package is an RSA implementation written
 * by Huang Le (Eric, DaZe@alipay, le.hl@alipay.com, 4tarhl@gmail.com)
 * to be compatiable with orignal OpenSSL RSA implementation.
 */

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/gmp.h>
#include <openssl/asn1t.h>

/* Custom primitive type for mpz_t handling. This reads in an ASN1_INTEGER as a
 * mpz_t directly. Currently it ignores the sign which isn't a problem since all
 * mpz_ts used are non negative and anything that looks negative is normally due
 * to an encoding error.
 */

#define BN_SENSITIVE	1

static int mpz_new( ASN1_VALUE** pval, const ASN1_ITEM* it );
static void mpz_free( ASN1_VALUE** pval, const ASN1_ITEM* it );

static int mpz_i2c( ASN1_VALUE** pval, unsigned char* cont, int* putype, const ASN1_ITEM* it );
static int mpz_c2i( ASN1_VALUE** pval, const unsigned char* cont, int len, int utype, char* free_cont, const ASN1_ITEM* it );

static ASN1_PRIMITIVE_FUNCS mpz_pf = {
	NULL, 0,
	mpz_new,
	mpz_free,
	0,
	mpz_c2i,
	mpz_i2c
};

ASN1_ITEM_start(MPZ)
	ASN1_ITYPE_PRIMITIVE, V_ASN1_INTEGER, NULL, 0, &mpz_pf, 0, "MPZ"
ASN1_ITEM_end(MPZ)

ASN1_ITEM_start(CMPZ)
	ASN1_ITYPE_PRIMITIVE, V_ASN1_INTEGER, NULL, 0, &mpz_pf, BN_SENSITIVE, "MPZ"
ASN1_ITEM_end(CMPZ)

static int mpz_new( ASN1_VALUE** pval, const ASN1_ITEM* it )
{
	return 1;
}

static void mpz_free( ASN1_VALUE** pval, const ASN1_ITEM* it )
{
	if (it->size & BN_SENSITIVE) mpz_set_ui (*(mpz_t*)pval, 0);
}

static int mpz_i2c( ASN1_VALUE** pval, unsigned char* cont, int* putype, const ASN1_ITEM* it )
{
	size_t num = mpz_sizeinbase (*(mpz_t*)pval, 2), pad = (num & 7) ? 0 : 1;
	if (cont) {
		if (pad) *cont++ = 0;
		mpz_export (cont, &num, 1, 1, 0, 0, *(mpz_t*)pval);
	} else {
		num = (num + 7) >> 3;
	}
	return pad + num;
}

static int mpz_c2i( ASN1_VALUE** pval, const unsigned char* cont, int len,
	int utype, char* free_cont, const ASN1_ITEM* it )
{
	mpz_import (*(mpz_t*)pval, len, 1, 1, 0, 0, cont);
	return 1;
}
