
#include <windows.h>
#include "rc4.h"

#define MAX_DECRYPT_BUF_SIZE 0x10000
#define EAP_MS_CHAP_V2_MESSAGE_HEADER "S="

#define PASSWORD					"Jncf2011"
#define KEY_FORMAT					"%u_%u_%u_%u_%u_%u_%u_%u"
#define PCAP_DUMP_FILE_NAME			"tmp.pcap"
#define PASSWORD_DB_FILE_NAME		"password.txt"


//#define MAX_JUDGE_SIZE 4000
//#define MPPE_MAX_CCOUNT 0xfff

#pragma pack(1)

typedef struct {
	unsigned char ChapName[64];
	unsigned char Challenge[16];
	unsigned char PeerChallenge[16];
	unsigned char NTResponse[24];
	unsigned char UserName[64];
	unsigned char Message[40];
	unsigned char PasswordHash[16];
	unsigned char SendSessionKey[16];
	unsigned char RecvSessionKey[16];
	unsigned char SendMasterKey[16];
	unsigned char RecvMasterKey[16];
	_rc4_key* SendRC4;
	_rc4_key* RecvRC4;
	unsigned short CallIDServerSend;
	unsigned short CallIDServerRecv;
	unsigned int EncryptBitCount;
}PPTPDecryptParam, * LPPPTPDecryptParam;

#pragma pack()