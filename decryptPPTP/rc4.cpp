
#include <windows.h>
#include "public_type.h"

static void swap_byte(uint8_t *a, uint8_t *b)
{
	uint8_t swapByte; 

	swapByte = *a; 
	*a = *b;      
	*b = swapByte;
}


void rc4_set_key(uint8_t *key_data_ptr, int key_data_len, _rc4_key *key)
{
	uint8_t index1;
	uint8_t index2;
	uint8_t* state;
	short counter;  

	state = &key->state[0];    
	for(counter = 0; counter < 256; counter++) 
	{
		state[counter] = (uint8_t)counter;
	}
	key->x = 0;
	key->y = 0;
	index1 = 0;
	index2 = 0;        
	for(counter = 0; counter < 256; counter++)
	{               
		index2 = (key_data_ptr[index1] + state[counter] + index2) % 256;                
		swap_byte(&state[counter], &state[index2]);            
		index1 = (index1 + 1) % key_data_len;  
	} 
}

void rc4_decrypt(uint8_t *buffer_ptr, int buffer_len, _rc4_key * key)
{
	uint8_t x;
	uint8_t y;
	uint8_t* state;
	uint8_t xorIndex;
	short counter;              

	x = key->x;     
	y = key->y;     

	state = &key->state[0];         
	for(counter = 0; counter < buffer_len; counter ++)      
	{               
		x = (x + 1) % 256;                      
		y = (state[x] + y) % 256;               
		swap_byte(&state[x], &state[y]);                        

		xorIndex = (state[x] + state[y]) % 256;                 

		buffer_ptr[counter] ^= state[xorIndex];         
	}               
	key->x = x;     
	key->y = y;
}



void rc4_encrypt(uint8_t *buffer_ptr, int buffer_len, _rc4_key * key)
{
	rc4_decrypt(buffer_ptr, buffer_len,  key);
}