#ifndef _SHA1_H
#define _SHA1_H



#include "public_type.h"

#define SHA1_MAC_LEN 20

#pragma pack(1)
typedef struct {
	uint32_t state[5];
	uint32_t count[2];
	unsigned char buffer[64];
} SHA1_CTX;
#pragma pack()

void SHA1Init(SHA1_CTX* context);
void SHA1Update(SHA1_CTX* context, unsigned char* data, uint32_t len);
void SHA1Final(unsigned char digest[20], SHA1_CTX* context);
void SHA1Transform(uint32_t state[5], unsigned char buffer[64]);

#endif /* SHA1_H */
