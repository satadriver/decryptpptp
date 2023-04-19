#include <windows.h>
#include "public_type.h"
#include "sha1.h"
#include "des.h"






void get_challenge(unsigned char *peer_challenge,unsigned char *  authenticator_challenge,unsigned char * username,unsigned char * challenge)
{
	uint8_t digest[SHA1_MAC_LEN] = {0};
	SHA1_CTX context;
	SHA1Init(&context);
	SHA1Update(&context, peer_challenge, 16);
	SHA1Update(&context, authenticator_challenge, 16);
	SHA1Update(&context, (uint8_t *)username, strlen((char*)username));
	SHA1Final(digest, &context);
	memcpy(challenge, digest, 8);
}



int check_chap_success(unsigned char *password_hash,unsigned char *peer_challenge,unsigned char *  authenticator_challenge,unsigned char * username,unsigned char * nt_response)
{
	unsigned char challenge[8] = {0}; 
	get_challenge(peer_challenge,authenticator_challenge,username,challenge);

	//pass_id = unit.pass_id;
	// get NT-Response
	uint8_t nt_response_check[24] = {0};
	uint8_t password_hash_3[7] = {0};
	memcpy(password_hash_3, password_hash + 14,2);

	DesEncrypt des_encrypt;
	des_encrypt.encrypt(challenge, password_hash, nt_response_check);
	des_encrypt.encrypt(challenge, password_hash + 7, nt_response_check + 8);
	des_encrypt.encrypt(challenge, password_hash_3, nt_response_check + 16);

	// compare NT-Response
	for (int i=0; i<24; i++)
	{
		if (nt_response[i] != nt_response_check[i])
		{
			return FALSE;
		}
	}
	return TRUE;
}


