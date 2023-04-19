
#include <windows.h>


int check_chap_success(unsigned char *password_hash,unsigned char *peer_challenge,unsigned char *  authenticator_challenge,unsigned char * username,unsigned char * nt_response);