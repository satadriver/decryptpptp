#include <windows.h>
#include "public_type.h"

int init_start_key(uint8_t * password_hash,uint8_t * nt_response,uint8_t *server_session_key,uint8_t *client_session_key,uint8_t * servermasterkey,uint8_t* clientmasterkey,int encryptbits);
void GetNewKeyFromSHA(uint8_t *StartKey, uint8_t *SessionKey, unsigned long SessionKeyLength, uint8_t *InterimKey);