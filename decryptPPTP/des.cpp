#include "des.h"

static const ufc_long longmask[32] = 
{
	0x80000000, 0x40000000, 0x20000000, 0x10000000,
	0x08000000, 0x04000000, 0x02000000, 0x01000000,
	0x00800000, 0x00400000, 0x00200000, 0x00100000,
	0x00080000, 0x00040000, 0x00020000, 0x00010000,
	0x00008000, 0x00004000, 0x00002000, 0x00001000,
	0x00000800, 0x00000400, 0x00000200, 0x00000100,
	0x00000080, 0x00000040, 0x00000020, 0x00000010,
	0x00000008, 0x00000004, 0x00000002, 0x00000001
};

static const unsigned char bytemask[8]  = 
{
	0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01
};

static const ufc_long BITMASK[24] = 
{
	0x40000000, 0x20000000, 0x10000000, 0x08000000, 0x04000000, 0x02000000,
	0x01000000, 0x00800000, 0x00400000, 0x00200000, 0x00100000, 0x00080000,
	0x00004000, 0x00002000, 0x00001000, 0x00000800, 0x00000400, 0x00000200,
	0x00000100, 0x00000080, 0x00000040, 0x00000020, 0x00000010, 0x00000008
};

static const int final_perm[64] = 
{
	40,  8, 48, 16, 56, 24, 64, 32, 39,  7, 47, 15, 55, 23, 63, 31,
	38,  6, 46, 14, 54, 22, 62, 30, 37,  5, 45, 13, 53, 21, 61, 29,
	36,  4, 44, 12, 52, 20, 60, 28, 35,  3, 43, 11, 51, 19, 59, 27,
	34,  2, 42, 10, 50, 18, 58, 26, 33,  1, 41,  9, 49, 17, 57, 25
};
static const int initial_perm[64] = 
{
	58, 50, 42, 34, 26, 18, 10,  2, 60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14,  6, 64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15, 7
};

/*
 * The sboxes
 */
static const int sbox[8][4][16]= 
{
    { 
		{ 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7 },
		{  0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8 },
		{  4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0 },
		{ 15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13 }
    },

    { 
		{ 15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10 },
		{  3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5 },
		{  0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15 },
		{ 13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9 }
    },

    { 
		{ 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8 },
		{ 13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1 },
		{ 13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7 },
		{  1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12 }
    },

    { 
		{  7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15 },
		{ 13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9 },
		{ 10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4 },
		{  3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14 }
    },

    { 
		{  2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9 },
		{ 14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6 },
		{  4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14 },
		{ 11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3 }
    },

    { 
		{ 12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11 },
		{ 10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8 },
		{  9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6 },
		{  4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13 }
    },

    { 
		{  4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1 },
		{ 13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6 },
		{  1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2 },
		{  6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12 }
    },

    { 
		{ 13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7 },
		{  1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2 },
		{  7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8 },
		{  2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 }
    }
};

/*
 * Permutation done on the
 * result of sbox lookups
 */
static const int perm32[32] = 
{
	16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
	2,   8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25
};
/*
 * The E expansion table which selects
 * bits from the 32 bit intermediate result.
 */
static const int esel[48] = 
{
	32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
	8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1
};
/*
 * Permutation giving the key
 * of the i' DES round
 */
static const int pc2[48] = 
{
	14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

/*
 * How much to rotate each 28 bit half of the pc1 permutated
 *  56 bit key before using pc2 to give the i' key
 */
static const int rots[16] = 
{
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};
/*
 * Permutation done once on the 56 bit
 *  key derived from the original 8 byte ASCII key.
 */
static const int pc1[56] = 
{
	57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
};

/*
 * Process the elements of the sb table permuting the
 * bits swapped in the expansion by the current salt.
 */

#ifdef _VPN_32
void DesEncrypt::shuffle_sb(long32 *k, ufc_long saltbits)
{
	ufc_long j;
	long32 x;
	for(j=4096; j--;) 
	{
		x = (k[0] ^ k[1]) & (long32)saltbits;
		*k++ ^= x;
		*k++ ^= x;
	}
}
#else
void DesEncrypt::shuffle_sb(long64 *k, ufc_long saltbits)
{
	ufc_long j;
	long64 x;
	for(j=4096; j--;) 
	{
		x = ((*k >> 32) ^ *k) & (long64)saltbits;
		*k++ ^= (x << 32) | x;
	}
}
#endif

#ifdef _VPN_32

/*
 * 32 bit version
 */
void DesEncrypt::_ufc_doit_r(ufc_long itr, crypt_data * __restrict __data, ufc_long *res)
{
	int i;
	long32 s, *k;
	long32 *sb01 = (long32*)__data->sb0;
	long32 *sb23 = (long32*)__data->sb2;
	long32 l1, l2, r1, r2;

	l1 = (long32)res[0]; l2 = (long32)res[1];
	r1 = (long32)res[2]; r2 = (long32)res[3];

	while(itr--) 
	{
		k = (long32*)__data->keysched;
		for(i=8; i--; ) 
		{
			s = *k++ ^ r1;
			l1 ^= SBA(sb01, s & 0xffff); l2 ^= SBA(sb01, (s & 0xffff)+4);
			l1 ^= SBA(sb01, s >>= 16  ); l2 ^= SBA(sb01, (s         )+4);
			s = *k++ ^ r2;
			l1 ^= SBA(sb23, s & 0xffff); l2 ^= SBA(sb23, (s & 0xffff)+4);
			l1 ^= SBA(sb23, s >>= 16  ); l2 ^= SBA(sb23, (s         )+4);

			s = *k++ ^ l1;
			r1 ^= SBA(sb01, s & 0xffff); r2 ^= SBA(sb01, (s & 0xffff)+4);
			r1 ^= SBA(sb01, s >>= 16  ); r2 ^= SBA(sb01, (s         )+4);
			s = *k++ ^ l2;
			r1 ^= SBA(sb23, s & 0xffff); r2 ^= SBA(sb23, (s & 0xffff)+4);
			r1 ^= SBA(sb23, s >>= 16  ); r2 ^= SBA(sb23, (s         )+4);
		}
		s=l1; l1=r1; r1=s; s=l2; l2=r2; r2=s;
	}
	res[0] = l1; res[1] = l2; res[2] = r1; res[3] = r2;
}

#else

/*
 * 64 bit version
 */
void DesEncrypt::_ufc_doit_r(ufc_long itr, crypt_data * __restrict __data, ufc_long *res)
{
	int i;
	long64 l, r, s, *k;
	register long64 *sb01 = (long64*)__data->sb0;
	register long64 *sb23 = (long64*)__data->sb2;

	l = (((long64)res[0]) << 32) | ((long64)res[1]);
	r = (((long64)res[2]) << 32) | ((long64)res[3]);

	while(itr--) 
	{
		k = (long64*)__data->keysched;
		for(i=8; i--; ) 
		{
			s = *k++ ^ r;
			l ^= SBA(sb23, (s       ) & 0xffff);
			l ^= SBA(sb23, (s >>= 16) & 0xffff);
			l ^= SBA(sb01, (s >>= 16) & 0xffff);
			l ^= SBA(sb01, (s >>= 16)         );

			s = *k++ ^ l;
			r ^= SBA(sb23, (s       ) & 0xffff);
			r ^= SBA(sb23, (s >>= 16) & 0xffff);
			r ^= SBA(sb01, (s >>= 16) & 0xffff);
			r ^= SBA(sb01, (s >>= 16)         );
		}
		s=l; l=r; r=s;
	}
	res[0] = l >> 32; res[1] = l & 0xffffffff;
	res[2] = r >> 32; res[3] = r & 0xffffffff;
}
#endif

void DesEncrypt::init_des_r(crypt_data * __restrict data)
{
	int comes_from_bit;
	int bit, sg;
	ufc_long j;
	ufc_long mask1, mask2;
	int e_inverse[64];
	small_tables_initialized = 0;
#ifdef _VPN_32
	long32 *sb[4];
	sb[0] = (long32*)data->sb0; sb[1] = (long32*)data->sb1;
	sb[2] = (long32*)data->sb2; sb[3] = (long32*)data->sb3;
#else
	long64 *sb[4];
	sb[0] = (long64*)data->sb0; sb[1] = (long64*)data->sb1;
	sb[2] = (long64*)data->sb2; sb[3] = (long64*)data->sb3;
#endif
	if(small_tables_initialized == 0) 
	{
		//Create the do_pc1 table used to affect pc1 permutation when generating keys
		memset((char*)do_pc1, 0, (int)sizeof(do_pc1));
		for(bit = 0; bit < 56; bit++) 
		{
			comes_from_bit  = pc1[bit] - 1;
			mask1 = bytemask[comes_from_bit % 8 + 1];
			mask2 = longmask[bit % 28 + 4];
			for(j = 0; j < 128; j++) 
			{
				if(j & mask1)
				{
					do_pc1[comes_from_bit / 8][bit / 28][j] |= mask2;
				}
			}
		}
		//Create the do_pc2 table used to affect pc2 permutation when generating keys
		memset((char*)do_pc2, 0, (int)sizeof(do_pc2));
		for(bit = 0; bit < 48; bit++) 
		{
			comes_from_bit  = pc2[bit] - 1;
			mask1 = bytemask[comes_from_bit % 7 + 1];
			mask2 = BITMASK[bit % 24];
			for(j = 0; j < 128; j++) 
			{
				if(j & mask1)
					do_pc2[comes_from_bit / 7][j] |= mask2;
			}
		}

/*
 * Now generate the table used to do combined
 * 32 bit permutation and e expansion
 *
 * We use it because we have to permute 16384 32 bit
 * longs into 48 bit in order to initialize sb.
 *
 * Looping 48 rounds per permutation becomes
 * just too slow...
 *
 */
		memset((char*)eperm32tab, 0, (int)sizeof(eperm32tab));
		for(bit = 0; bit < 48; bit++) 
		{
			ufc_long mask1,comes_from;
			comes_from = perm32[esel[bit]-1]-1;
			mask1  = bytemask[comes_from % 8];
			for(j = 256; j--;) 
			{
				if(j & mask1)
					eperm32tab[comes_from / 8][j][bit / 24] |= BITMASK[bit % 24];
			}
		}
    /*
     * Create an inverse matrix for esel telling
     * where to plug out bits if undoing it
     */
		for(bit=48; bit--;) 
		{
			e_inverse[esel[bit] - 1] = bit;
			e_inverse[esel[bit] - 1 + 32] = bit + 48;
		}
    /*
     * create efp: the matrix used to
     * undo the E expansion and effect final permutation
     */
		memset((char*)efp, 0, (int)sizeof(efp));
		for(bit = 0; bit < 64; bit++) 
		{
			int o_bit, o_long;
			ufc_long word_value, mask1, mask2;
			int comes_from_f_bit, comes_from_e_bit;
			int comes_from_word, bit_within_word;
			/* See where bit i belongs in the two 32 bit long's */
			o_long = bit / 32; /* 0..1  */
			o_bit  = bit % 32; /* 0..31 */
			/*
			* And find a bit in the e permutated value setting this bit.
			*
			* Note: the e selection may have selected the same bit several
			* times. By the initialization of e_inverse, we only look
			* for one specific instance.
			*/
			comes_from_f_bit = final_perm[bit] - 1;         /* 0..63 */
			comes_from_e_bit = e_inverse[comes_from_f_bit]; /* 0..95 */
			comes_from_word  = comes_from_e_bit / 6;        /* 0..15 */
			bit_within_word  = comes_from_e_bit % 6;        /* 0..5  */

			mask1 = longmask[bit_within_word + 26];
			mask2 = longmask[o_bit];

			for(word_value = 64; word_value--;) 
			{
				if(word_value & mask1)
					efp[comes_from_word][word_value][o_long] |= mask2;
			}
		}
		small_tables_initialized = 1;
	}
  /*
   * Create the sb tables:
   *
   * For each 12 bit segment of an 48 bit intermediate
   * result, the sb table precomputes the two 4 bit
   * values of the sbox lookups done with the two 6
   * bit halves, shifts them to their proper place,
   * sends them through perm32 and finally E expands
   * them so that they are ready for the next
   * DES round.
   *
   */
	memset((char*)data->sb0, 0, (int)sizeof(data->sb0));
	memset((char*)data->sb1, 0, (int)sizeof(data->sb1));
	memset((char*)data->sb2, 0, (int)sizeof(data->sb2));
	memset((char*)data->sb3, 0, (int)sizeof(data->sb3));
	for(sg = 0; sg < 4; sg++) 
	{
		int j1, j2;
		int s1, s2;
		for(j1 = 0; j1 < 64; j1++) 
		{
			s1 = s_lookup(2 * sg, j1);
			for(j2 = 0; j2 < 64; j2++) 
			{
			ufc_long to_permute, inx;
			s2 = s_lookup(2 * sg + 1, j2);
			to_permute = (((ufc_long)s1 << 4)  |
			(ufc_long)s2) << (24 - 8 * (ufc_long)sg);
#ifdef _VPN_32
			inx = ((j1 << 6)  | j2) << 1;
			sb[sg][inx  ]  = eperm32tab[0][(to_permute >> 24) & 0xff][0];
			sb[sg][inx+1]  = eperm32tab[0][(to_permute >> 24) & 0xff][1];
			sb[sg][inx  ] |= eperm32tab[1][(to_permute >> 16) & 0xff][0];
			sb[sg][inx+1] |= eperm32tab[1][(to_permute >> 16) & 0xff][1];
			sb[sg][inx  ] |= eperm32tab[2][(to_permute >>  8) & 0xff][0];
			sb[sg][inx+1] |= eperm32tab[2][(to_permute >>  8) & 0xff][1];
			sb[sg][inx  ] |= eperm32tab[3][(to_permute)       & 0xff][0];
			sb[sg][inx+1] |= eperm32tab[3][(to_permute)       & 0xff][1];
#else
			inx = ((j1 << 6)  | j2);
			sb[sg][inx]  =
				((long64)eperm32tab[0][(to_permute >> 24) & 0xff][0] << 32) |
				(long64)eperm32tab[0][(to_permute >> 24) & 0xff][1];
			sb[sg][inx] |=
				((long64)eperm32tab[1][(to_permute >> 16) & 0xff][0] << 32) |
				(long64)eperm32tab[1][(to_permute >> 16) & 0xff][1];
			sb[sg][inx] |=
				((long64)eperm32tab[2][(to_permute >>  8) & 0xff][0] << 32) |
				(long64)eperm32tab[2][(to_permute >>  8) & 0xff][1];
			sb[sg][inx] |=
				((long64)eperm32tab[3][(to_permute)       & 0xff][0] << 32) |
				(long64)eperm32tab[3][(to_permute)       & 0xff][1];
#endif
			}
		}
	}
	data->current_saltbits = 0;
	data->current_salt[0] = 0;
	data->current_salt[1] = 0;
	data->initialized++;
}


/*
 * Setup the unit for a new salt
 * Hopefully we'll not see a new salt in each crypt call.
 */
void DesEncrypt::_ufc_setup_salt_r(const char *s, crypt_data * __restrict data)
{
	ufc_long i, j, saltbits;
	if(data->initialized == 0)
	init_des_r(data);
	if(s[0] == data->current_salt[0] && s[1] == data->current_salt[1])
		return;
	data->current_salt[0] = s[0]; data->current_salt[1] = s[1];
	/*
	* This is the only crypt change to DES:
	* entries are swapped in the expansion table
	* according to the bits set in the salt.
	*/
	saltbits = 0;
	for(i = 0; i < 2; i++) 
	{
		long c=ascii_to_bin(s[i]);
		for(j = 0; j < 6; j++) 
		{
			if((c >> j) & 0x1)
				saltbits |= BITMASK[6 * i + j];
		}
	}
	/*
	* Permute the sb table values
	* to reflect the changed e
	* selection table
	*/
#ifdef _VPN_32
	#define LONGG long32*
#else
	#define LONGG long64*
#endif
	shuffle_sb((LONGG)data->sb0, data->current_saltbits ^ saltbits);
	shuffle_sb((LONGG)data->sb1, data->current_saltbits ^ saltbits);
	shuffle_sb((LONGG)data->sb2, data->current_saltbits ^ saltbits);
	shuffle_sb((LONGG)data->sb3, data->current_saltbits ^ saltbits);
	data->current_saltbits = saltbits;
}

void DesEncrypt::_ufc_mk_keytab_r(const char *key, crypt_data * __restrict data)
{
	ufc_long v1, v2, *k1;
	int i;
#ifdef _VPN_32
	long32 v, *k2;
	k2 = (long32*)data->keysched;
#else
	long64 v, *k2;
	k2 = (long64*)data->keysched;
#endif
	v1 = v2 = 0; k1 = &do_pc1[0][0][0];
	for(i = 8; i--;) 
	{
		v1 |= k1[*key   & 0x7f]; k1 += 128;
		v2 |= k1[*key++ & 0x7f]; k1 += 128;
	}
	for(i = 0; i < 16; i++) 
	{
		k1 = &do_pc2[0][0];
		v1 = (v1 << rots[i]) | (v1 >> (28 - rots[i]));
		v  = k1[(v1 >> 21) & 0x7f]; k1 += 128;
		v |= k1[(v1 >> 14) & 0x7f]; k1 += 128;
		v |= k1[(v1 >>  7) & 0x7f]; k1 += 128;
		v |= k1[(v1      ) & 0x7f]; k1 += 128;

#ifdef _VPN_32
		*k2++ = (v | 0x00008000);
		v = 0;
#else
		v = (v << 32);
#endif
		v2 = (v2 << rots[i]) | (v2 >> (28 - rots[i]));
		v |= k1[(v2 >> 21) & 0x7f]; k1 += 128;
		v |= k1[(v2 >> 14) & 0x7f]; k1 += 128;
		v |= k1[(v2 >>  7) & 0x7f]; k1 += 128;
		v |= k1[(v2      ) & 0x7f];
#ifdef _VPN_32
		*k2++ = (v | 0x00008000);
#else
		*k2++ = v | 0x0000800000008000l;
#endif
	}
	data->direction = 0;
}

void DesEncrypt::setkey_r(const unsigned char * key, crypt_data * __restrict data)
{
	int i,j;
	unsigned char c;
	unsigned char ktab[8];

	_ufc_setup_salt_r("..", data); /* be sure we're initialized */

	for(i = 0; i < 8; i++) 
	{
		for(j = 0, c = 0; j < 8; j++)
		{
			c = c << 1 | *key++;
		}
		ktab[i] = c >> 1;
	}
	_ufc_mk_keytab_r((char *)ktab, data);
}


void DesEncrypt::_ufc_dofinalperm_r(ufc_long *res, crypt_data * __restrict data)
{
	ufc_long v1, v2, x;
	ufc_long l1,l2,r1,r2;

	l1 = res[0]; l2 = res[1];
	r1 = res[2]; r2 = res[3];

	x = (l1 ^ l2) & data->current_saltbits; l1 ^= x; l2 ^= x;
	x = (r1 ^ r2) & data->current_saltbits; r1 ^= x; r2 ^= x;

	v1=v2=0; l1 >>= 3; l2 >>= 3; r1 >>= 3; r2 >>= 3;

	v1 |= efp[15][ r2         & 0x3f][0]; v2 |= efp[15][ r2 & 0x3f][1];
	v1 |= efp[14][(r2 >>= 6)  & 0x3f][0]; v2 |= efp[14][ r2 & 0x3f][1];
	v1 |= efp[13][(r2 >>= 10) & 0x3f][0]; v2 |= efp[13][ r2 & 0x3f][1];
	v1 |= efp[12][(r2 >>= 6)  & 0x3f][0]; v2 |= efp[12][ r2 & 0x3f][1];

	v1 |= efp[11][ r1         & 0x3f][0]; v2 |= efp[11][ r1 & 0x3f][1];
	v1 |= efp[10][(r1 >>= 6)  & 0x3f][0]; v2 |= efp[10][ r1 & 0x3f][1];
	v1 |= efp[ 9][(r1 >>= 10) & 0x3f][0]; v2 |= efp[ 9][ r1 & 0x3f][1];
	v1 |= efp[ 8][(r1 >>= 6)  & 0x3f][0]; v2 |= efp[ 8][ r1 & 0x3f][1];

	v1 |= efp[ 7][ l2         & 0x3f][0]; v2 |= efp[ 7][ l2 & 0x3f][1];
	v1 |= efp[ 6][(l2 >>= 6)  & 0x3f][0]; v2 |= efp[ 6][ l2 & 0x3f][1];
	v1 |= efp[ 5][(l2 >>= 10) & 0x3f][0]; v2 |= efp[ 5][ l2 & 0x3f][1];
	v1 |= efp[ 4][(l2 >>= 6)  & 0x3f][0]; v2 |= efp[ 4][ l2 & 0x3f][1];

	v1 |= efp[ 3][ l1         & 0x3f][0]; v2 |= efp[ 3][ l1 & 0x3f][1];
	v1 |= efp[ 2][(l1 >>= 6)  & 0x3f][0]; v2 |= efp[ 2][ l1 & 0x3f][1];
	v1 |= efp[ 1][(l1 >>= 10) & 0x3f][0]; v2 |= efp[ 1][ l1 & 0x3f][1];
	v1 |= efp[ 0][(l1 >>= 6)  & 0x3f][0]; v2 |= efp[ 0][ l1 & 0x3f][1];

	res[0] = v1; res[1] = v2;
}
void DesEncrypt::encrypt_r(unsigned char * block, int edflag, crypt_data * __restrict data)
{
	ufc_long l1, l2, r1, r2, res[4];
	int i;
#ifdef _VPN_32
	long32 *kt;
	kt = (long32*)data->keysched;
#else
	long64 *kt;
	kt = (long64*)data->keysched;
#endif
  /*
   * Undo any salt changes to E expansion
   */
	_ufc_setup_salt_r("..", data);

  /*
   * Reverse key table if
   * changing operation (encrypt/decrypt)
   */
	if((edflag == 0) != (data->direction == 0)) 
	{
		for(i = 0; i < 8; i++) 
		{
#ifdef _VPN_32
			long32 x;
			x = kt[2 * (15-i)];
			kt[2 * (15-i)] = kt[2 * i];
			kt[2 * i] = x;

			x = kt[2 * (15-i) + 1];
			kt[2 * (15-i) + 1] = kt[2 * i + 1];
			kt[2 * i + 1] = x;
#else
			long64 x;
			x = kt[15-i];
			kt[15-i] = kt[i];
			kt[i] = x;
#endif
		}
		data->direction = edflag;
	}

  /*
   * Do initial permutation + E expansion
   */
	i = 0;
	for(l1 = 0; i < 24; i++) 
	{
		if(block[initial_perm[esel[i]-1]-1])
			l1 |= BITMASK[i];
	}
	for(l2 = 0; i < 48; i++) 
	{
		if(block[initial_perm[esel[i]-1]-1])
			l2 |= BITMASK[i-24];
	}

	i = 0;
	for(r1 = 0; i < 24; i++) 
	{
		if(block[initial_perm[esel[i]-1+32]-1])
			r1 |= BITMASK[i];
	}
	for(r2 = 0; i < 48; i++) 
	{
		if(block[initial_perm[esel[i]-1+32]-1])
			r2 |= BITMASK[i-24];
	}

  /*
   * Do DES inner loops + final conversion
   */
	res[0] = l1; res[1] = l2;
	res[2] = r1; res[3] = r2;
	_ufc_doit_r((ufc_long)1, data, &res[0]); //crypt.cpp

  /*
   * Do final permutations
   */
	_ufc_dofinalperm_r(res, data);

  /*
   * And convert to bit array
   */
	l1 = res[0]; r1 = res[1];
	for(i = 0; i < 32; i++) 
	{
		*block++ = (l1 & longmask[i]) != 0;
	}
	for(i = 0; i < 32; i++) 
	{
		*block++ = (r1 & longmask[i]) != 0;
	}
}

void DesEncrypt::Expand(unsigned char *in, unsigned char *out)
{
	int j, c;
	int i;

	for (i = 0; i < 64; in++) 
	{
		c = *in;
		for (j = 7; j >= 0; j--)
		{
			 *out++ = (c >> j) & 1;
		}
		i += 8;
	}
}

void DesEncrypt::Collapse(unsigned char *in, unsigned char *out)
{
	int j;
	int i;
	unsigned int c;

	for (i = 0; i < 64; i += 8, out++) 
	{
		c = 0;
		for (j = 7; j >= 0; j--, in++)
		{
			c |= *in << j;
		}
		*out = c & 0xff;
	}
}

unsigned char DesEncrypt::Get7Bits(unsigned char *input, int startBit)
{
	register unsigned int word;
	word = (unsigned) input[startBit / 8] << 8;
	word |= (unsigned) input[startBit / 8 + 1];
	word >>= 15 - (startBit % 8 + 7);
	return word & 0xFE;
}

void DesEncrypt::MakeKey(unsigned char *key, unsigned char *des_key)
{
	des_key[0] = Get7Bits(key, 0);
	des_key[1] = Get7Bits(key, 7);
	des_key[2] = Get7Bits(key, 14);
	des_key[3] = Get7Bits(key, 21);
	des_key[4] = Get7Bits(key, 28);
	des_key[5] = Get7Bits(key, 35);
	des_key[6] = Get7Bits(key, 42);
	des_key[7] = Get7Bits(key, 49);
}

void DesEncrypt::encrypt(unsigned char *clear, unsigned char *key, unsigned char *cipher)
{
	crypt_data ufc_foobar;
	ufc_foobar.initialized = 0;
	unsigned char des_key[8] = {0};
	unsigned char crypt_key[64] = {0};
	unsigned char des_input[64] = {0};

	MakeKey(key, des_key);

	Expand(des_key, crypt_key);
	setkey_r(crypt_key, &ufc_foobar);

	Expand(clear, des_input);
	encrypt_r(des_input, 0, &ufc_foobar);

	Collapse(des_input, cipher);
}
