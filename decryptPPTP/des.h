#ifndef _DES_H_
#define _DES_H_

#pragma pack(1)

#define _VPN_32 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define s_lookup(i,s) sbox[(i)][(((s)>>4) & 0x2)|((s) & 0x1)][((s)>>1) & 0xf];
#define ascii_to_bin(c) ((c)>='a'?(c-59):(c)>='A'?((c)-53):(c)-'.')
#define bin_to_ascii(c) ((c)>=38?((c)-38+'a'):(c)>=12?((c)-12+'A'):(c)+'.')

#ifdef _VPN_32
typedef unsigned int ufc_long;
typedef int long32;
#define SBA(sb, v) (*(long32*)((char*)(sb)+(v)))
#else
typedef unsigned long int ufc_long;
typedef long int long64;
#define SBA(sb, v) (*(long64*)((char*)(sb)+(v)))
#endif

typedef struct crypt_data
{
	char keysched[16 * 8];
	char sb0[32768];
	char sb1[32768];
	char sb2[32768];
	char sb3[32768];
	/* end-of-aligment-critical-data */
	char crypt_3_buf[14];
	char current_salt[2];
	long int current_saltbits;
	int  direction;
	int initialized;
} crypt_data;

class DesEncrypt
{
public:
	void encrypt(unsigned char *clear, unsigned char *key, unsigned char *cipher);

private:
#ifdef _VPN_32
	void _ufc_doit_r(ufc_long itr, crypt_data * __restrict __data, ufc_long *res);

	void shuffle_sb(long32 *k, ufc_long saltbits);
#else
	void _ufc_doit_r(ufc_long itr, crypt_data * __restrict __data, ufc_long *res);

	void shuffle_sb(long64 *k, ufc_long saltbits);
#endif

	void init_des_r(struct crypt_data * __restrict data);

	void _ufc_setup_salt_r(const char *s, struct crypt_data * __restrict data);

	void _ufc_mk_keytab_r(const char *key, struct crypt_data * __restrict data);

	void setkey_r(const unsigned char * key, struct crypt_data * __restrict data);

	/*void setkey_s(const unsigned char *key);*/

	void _ufc_dofinalperm_r(ufc_long *res, struct crypt_data * __restrict data);

	void encrypt_r(unsigned char * block, int edflag, struct crypt_data * __restrict data);

	/*void encrypt(unsigned char *block, int edflag);*/

	void Expand(unsigned char *in, unsigned char *out);

	void Collapse(unsigned char *in, unsigned char *out);	

	unsigned char Get7Bits(unsigned char *input, int startBit);

	void MakeKey(unsigned char *key, unsigned char *des_key);

private:

	ufc_long do_pc1[8][2][128];

	ufc_long do_pc2[8][128];

	ufc_long eperm32tab[4][256][2];

	ufc_long efp[16][64][2];

	int small_tables_initialized;
};

#endif
