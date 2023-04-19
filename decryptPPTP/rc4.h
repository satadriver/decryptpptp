
#include <windows.h>

#include "public_type.h"

void rc4_encrypt(uint8_t *buffer_ptr, int buffer_len, _rc4_key * key);
void rc4_decrypt(uint8_t *buffer_ptr, int buffer_len, _rc4_key * key);

void rc4_set_key(uint8_t *key_data_ptr, int key_data_len, _rc4_key *key);