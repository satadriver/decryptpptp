


#include <stdio.h>
#include <WINSOCK2.H>
#include <windows.h>
#include "Packet.h"
#include "public_type.h"
#include "include\\pcap.h"
#include "include\\pcap\\pcap.h"
#include <map>
#include <string>
#include "capture.h"
#include "md4.h"
#include "sha1.h"
#include "des.h"
#include "chap.h"
#include "sessionkey.h"
#include "rc4.h"
#include "mppcdecom.h"
#include "publicfunc.h"
#include "decryptpptp.h"

using namespace std;


map <string, PPTPDecryptParam> mapPPTPDecryptParam;


int GetPasswordFromDataBase(LPPPTPDecryptParam lpparam) {
	HANDLE hf = CreateFileA(PASSWORD_DB_FILE_NAME, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hf != INVALID_HANDLE_VALUE)
	{
		int filesize = GetFileSize(hf, 0);
		if (filesize <= 0)
		{
			CloseHandle(hf);
			WriteLogFile("password database not found\r\n");
			return FALSE;
		}
		char* lppwbuf = new char[filesize + 0x1000];
		DWORD dwcnt = 0;

		int ret = ReadFile(hf, lppwbuf, filesize, &dwcnt, 0);
		*(lppwbuf + filesize) = 0;
		CloseHandle(hf);

		char* hdr = lppwbuf;
		for (int i = 0; i < filesize; i++)
		{
			if (*(lppwbuf + i) == 0x0d && *(lppwbuf + i + 1) == 0x0a)
			{
				*(lppwbuf + i) = 0;
				*(lppwbuf + i + 1) = 0;
				wchar_t* passwordunicode = GB2312ToUnicode(hdr);
				uint8_t password_hash[16] = { 0 };
				md4((unsigned char*)passwordunicode, wcslen((wchar_t*)passwordunicode) * 2, password_hash);
				delete[]passwordunicode;

				int ret = check_chap_success(password_hash, lpparam->PeerChallenge, lpparam->Challenge, lpparam->UserName, lpparam->NTResponse);
				if (ret)
				{
					memcpy(lpparam->PasswordHash, password_hash, 16);
					ret = init_start_key(password_hash, lpparam->NTResponse, lpparam->SendSessionKey, lpparam->RecvSessionKey,
						lpparam->SendMasterKey, lpparam->RecvMasterKey, lpparam->EncryptBitCount);
					if (ret == FALSE)
					{
						return FALSE;
					}
					else {
						lpparam->RecvRC4 = new _rc4_key;
						lpparam->SendRC4 = new _rc4_key;
						return TRUE;
					}
				}

				hdr = lppwbuf + i + 2;
			}
		}
	}
	return FALSE;
}





void procpcapfile(char* user, const struct pcap_pkthdr* header, const u_char* pkt_data) {
	if (header->caplen != header->len || header->caplen >= 0x1000 || header->len >= 0x1000)
	{
		printf("caplen:%d len:%d\r\n", header->caplen, header->len);
		WriteLogFile("caplen is not equal to len\r\n");
		return;
	}
	char pdata[0x1000];
	memcpy(pdata, (char*)pkt_data, header->caplen);
	*(pdata + header->caplen) = 0;

	LPMACHEADER pMac = (LPMACHEADER)pdata;
	if (pMac->Protocol != 0x0008)
	{
		//WriteLogFile("mot mac header packet\r\n");
		return;
	}

	LPIPHEADER pIPHdr = (LPIPHEADER)(pdata + sizeof(MACHEADER));
	if (pIPHdr->Version != 4)
	{
		//WriteLogFile("mot ip packet\r\n");
		return;
	}


	if (pIPHdr->Protocol != 0x2f)
	{
		return;
	}

	//int iIpLen = ntohs(pIPHdr->PacketSize);
	int iIpHdrLen = pIPHdr->HeaderSize << 2;

	LPGREHEADER lpgrehdr = (LPGREHEADER)(pdata + sizeof(MACHEADER) + iIpHdrLen);
	LPPPTPDATAHDR lppptpdatahdr = 0;
	char* lppptpdata = 0;
	int pptpdatalen = 0;
	if ((lpgrehdr->Flags == 0x0130 || lpgrehdr->Flags == 0x8130) && lpgrehdr->ProtocolType == 0x0b88)
	{
		int GreHdrSize = 0;
		if (lpgrehdr->Flags == 0x8130)
		{
			LPGREACKHEADER lpgreackhdr = (LPGREACKHEADER)lpgrehdr;
			GreHdrSize = sizeof(GREACKHEADER);
		}
		else if (lpgrehdr->Flags == 0x0130) {
			GreHdrSize = sizeof(GREHEADER);
		}
		else {
			WriteLogFile("gre error packet\r\n");
			return;
		}

		unsigned char protocol = *(unsigned char*)(pdata + sizeof(MACHEADER) + iIpHdrLen + GreHdrSize);
		if (protocol == 0xfd)
		{
			lppptpdatahdr = (LPPPTPDATAHDR)(pdata + sizeof(MACHEADER) + iIpHdrLen + GreHdrSize + 1);
			lppptpdata = (pdata + sizeof(MACHEADER) + iIpHdrLen + GreHdrSize + 1 + sizeof(PPTPDATAHDR));
			pptpdatalen = header->caplen - (sizeof(MACHEADER) + iIpHdrLen + GreHdrSize + 1 + sizeof(PPTPDATAHDR));

			char strkey[1024];
			unsigned char srcip[4];
			unsigned char dstip[4];
			memcpy(srcip, (char*)&pIPHdr->SrcIP, 4);
			memcpy(dstip, (char*)&pIPHdr->DstIP, 4);
			sprintf(strkey, KEY_FORMAT, srcip[0], srcip[1], srcip[2], srcip[3], dstip[0], dstip[1], dstip[2], dstip[3]);

			if (lppptpdatahdr->isencrypted == 0)
			{
				WriteLogFile("gre packet not encrypted\r\n");
				//MessageBoxA(0,"not encrypt packet","not encrypt packet",MB_OK);
			}

			if (lppptpdatahdr->isencrypted)
			{
				map<string, PPTPDecryptParam>::iterator it;

				string key = string(strkey);
				it = mapPPTPDecryptParam.find(key);
				if (it != mapPPTPDecryptParam.end())
				{
					if (it->second.CallIDServerSend == lpgrehdr->CallID)
					{
						uint8_t interim_key[20] = { 0 };
						GetNewKeyFromSHA(it->second.SendMasterKey, it->second.SendSessionKey, MPPE_MAX_KEY_LEN, interim_key);
						rc4_set_key(interim_key, MPPE_MAX_KEY_LEN, it->second.SendRC4);
						rc4_encrypt(interim_key, MPPE_MAX_KEY_LEN, it->second.SendRC4);
						memcpy(it->second.SendSessionKey, interim_key, MPPE_MAX_KEY_LEN);

						rc4_set_key(it->second.SendSessionKey, 16, it->second.SendRC4);
						rc4_decrypt((unsigned char*)lppptpdata, pptpdatalen, it->second.SendRC4);
					}
					else if (it->second.CallIDServerRecv == lpgrehdr->CallID) {
						uint8_t interim_key[20] = { 0 };
						GetNewKeyFromSHA(it->second.RecvMasterKey, it->second.RecvSessionKey, 16, interim_key);
						rc4_set_key(interim_key, MPPE_MAX_KEY_LEN, it->second.RecvRC4);
						rc4_encrypt(interim_key, MPPE_MAX_KEY_LEN, it->second.RecvRC4);
						memcpy(it->second.RecvSessionKey, interim_key, MPPE_MAX_KEY_LEN);

						rc4_set_key(it->second.RecvSessionKey, 16, it->second.RecvRC4);
						rc4_decrypt((unsigned char*)lppptpdata, pptpdatalen, it->second.RecvRC4);
					}
					else {
						WriteLogFile("call id error\r\n");
						return;
					}
				}
				else {
					sprintf(strkey, KEY_FORMAT, dstip[0], dstip[1], dstip[2], dstip[3], srcip[0], srcip[1], srcip[2], srcip[3]);
					key = string(strkey);
					it = mapPPTPDecryptParam.find(key);
					if (it != mapPPTPDecryptParam.end())
					{
						if (it->second.CallIDServerSend == lpgrehdr->CallID)
						{
							uint8_t interim_key[20] = { 0 };
							GetNewKeyFromSHA(it->second.SendMasterKey, it->second.SendSessionKey, MPPE_MAX_KEY_LEN, interim_key);
							rc4_set_key(interim_key, MPPE_MAX_KEY_LEN, it->second.SendRC4);
							rc4_encrypt(interim_key, MPPE_MAX_KEY_LEN, it->second.SendRC4);
							memcpy(it->second.SendSessionKey, interim_key, MPPE_MAX_KEY_LEN);

							rc4_set_key(it->second.SendSessionKey, 16, it->second.SendRC4);
							rc4_decrypt((unsigned char*)lppptpdata, pptpdatalen, it->second.SendRC4);
						}
						else if (it->second.CallIDServerRecv == lpgrehdr->CallID)
						{
							uint8_t interim_key[20] = { 0 };
							GetNewKeyFromSHA(it->second.RecvMasterKey, it->second.RecvSessionKey, 16, interim_key);
							rc4_set_key(interim_key, MPPE_MAX_KEY_LEN, it->second.RecvRC4);
							rc4_encrypt(interim_key, MPPE_MAX_KEY_LEN, it->second.RecvRC4);
							memcpy(it->second.RecvSessionKey, interim_key, MPPE_MAX_KEY_LEN);

							rc4_set_key(it->second.RecvSessionKey, 16, it->second.RecvRC4);
							rc4_decrypt((unsigned char*)lppptpdata, pptpdatalen, it->second.RecvRC4);
						}
						else
						{
							WriteLogFile("call id error\r\n");
							return;
						}
					}
					else {
						WriteLogFile("not find in map\r\n");
						return;
					}
				}
			}

			if (lppptpdatahdr->iscompress)
			{
				unsigned char outputbuf[MAX_DECRYPT_BUF_SIZE];
				int outputsize = mppc_decompress((unsigned char*)lppptpdata, outputbuf, pptpdatalen, MAX_DECRYPT_BUF_SIZE);
				FILE* fp = fopen(strkey, "a+");
				int ret = fwrite(&outputsize, 4, 1, fp);
				ret = fwrite(outputbuf, outputsize, 1, fp);
				fclose(fp);
			}
			else {
				FILE* fp = fopen(strkey, "a+");
				int ret = fwrite(&pptpdatalen, 4, 1, fp);
				ret = fwrite(lppptpdata, pptpdatalen, 1, fp);
				fclose(fp);
			}

			return;
		}
		else {
			unsigned short protocol = *(unsigned short*)(pdata + sizeof(MACHEADER) + iIpHdrLen + GreHdrSize);
			if (protocol == 0x27c2)
			{
				LPEAPCHALLENGE lpeap = (LPEAPCHALLENGE)(pdata + sizeof(MACHEADER) + iIpHdrLen + GreHdrSize + 2);
				if (lpeap->Type == 26 && lpeap->EAPid == 1)
				{
					int EapHdrSize = 0;
					if (lpeap->EAPopcode == 1)
					{
						LPEAPCHALLENGE lpeapchallenge = (LPEAPCHALLENGE)lpeap;
						char strkey[1024];
						unsigned char srcip[4];
						unsigned char dstip[4];
						memcpy(srcip, (char*)&pIPHdr->SrcIP, 4);
						memcpy(dstip, (char*)&pIPHdr->DstIP, 4);
						sprintf((char*)strkey, KEY_FORMAT, srcip[0], srcip[1], srcip[2], srcip[3], dstip[0], dstip[1], dstip[2], dstip[3]);
						map<string, PPTPDecryptParam>::iterator it;

						string key = string((char*)strkey);
						it = mapPPTPDecryptParam.find(key);
						if (it != mapPPTPDecryptParam.end())
						{
							memcpy(it->second.Challenge, lpeapchallenge->EAPchallenge, 16);
							strcpy((char*)it->second.ChapName, (char*)lpeapchallenge->EAPname);
							it->second.CallIDServerSend = lpgrehdr->CallID;
						}
						else {
							sprintf((char*)strkey, KEY_FORMAT, dstip[0], dstip[1], dstip[2], dstip[3], srcip[0], srcip[1], srcip[2], srcip[3]);
							key = string((char*)strkey);
							it = mapPPTPDecryptParam.find(key);
							if (it != mapPPTPDecryptParam.end())
							{
								memcpy(it->second.Challenge, lpeapchallenge->EAPchallenge, 16);
								strcpy((char*)it->second.ChapName, (char*)lpeapchallenge->EAPname);
								it->second.CallIDServerSend = lpgrehdr->CallID;
							}
							else {
								PPTPDecryptParam param = { 0 };
								param.CallIDServerSend = lpgrehdr->CallID;
								memcpy(param.Challenge, lpeapchallenge->EAPchallenge, 16);
								strcpy((char*)param.ChapName, (char*)lpeapchallenge->EAPname);
								mapPPTPDecryptParam.insert(pair<string, PPTPDecryptParam>(key, param));
							}
						}
					}
					else if (lpeap->EAPopcode == 2)
					{
						LPEAPRESPONSE lpeapresponse = (LPEAPRESPONSE)lpeap;
						char strkey[1024];
						unsigned char srcip[4];
						unsigned char dstip[4];
						memcpy(srcip, (char*)&pIPHdr->SrcIP, 4);
						memcpy(dstip, (char*)&pIPHdr->DstIP, 4);
						sprintf(strkey, KEY_FORMAT, srcip[0], srcip[1], srcip[2], srcip[3], dstip[0], dstip[1], dstip[2], dstip[3]);
						map<string, PPTPDecryptParam>::iterator it;

						string key = string(strkey);
						it = mapPPTPDecryptParam.find(key);
						if (it != mapPPTPDecryptParam.end())
						{
							memcpy(it->second.PeerChallenge, lpeapresponse->EAPpeerchallenge, 16);
							memcpy(it->second.NTResponse, lpeapresponse->EAPntresponse, 24);

							strcpy((char*)it->second.UserName, (char*)lpeapresponse->EAPusername);
							it->second.CallIDServerRecv = lpgrehdr->CallID;
						}
						else {
							sprintf(strkey, KEY_FORMAT, dstip[0], dstip[1], dstip[2], dstip[3], srcip[0], srcip[1], srcip[2], srcip[3]);
							key = string(strkey);
							it = mapPPTPDecryptParam.find(key);
							if (it != mapPPTPDecryptParam.end())
							{
								memcpy(it->second.PeerChallenge, lpeapresponse->EAPpeerchallenge, 16);
								memcpy(it->second.NTResponse, lpeapresponse->EAPntresponse, 24);
								it->second.CallIDServerRecv = lpgrehdr->CallID;
								strcpy((char*)it->second.UserName, (char*)lpeapresponse->EAPusername);
							}
							else {
								PPTPDecryptParam param = { 0 };
								memcpy(param.PeerChallenge, lpeapresponse->EAPpeerchallenge, 16);
								memcpy(it->second.NTResponse, lpeapresponse->EAPntresponse, 24);

								mapPPTPDecryptParam.insert(pair<string, PPTPDecryptParam>(key, param));
								strcpy((char*)it->second.UserName, (char*)lpeapresponse->EAPusername);
								it->second.CallIDServerRecv = lpgrehdr->CallID;
							}
						}
					}
					else if (lpeap->EAPopcode == 3)
					{
						LPEAPRESULT lpeapresult = (LPEAPRESULT)lpeap;
						char strkey[1024];
						unsigned char srcip[4];
						unsigned char dstip[4];
						memcpy(srcip, (char*)&pIPHdr->SrcIP, 4);
						memcpy(dstip, (char*)&pIPHdr->DstIP, 4);
						sprintf(strkey, KEY_FORMAT, srcip[0], srcip[1], srcip[2], srcip[3], dstip[0], dstip[1], dstip[2], dstip[3]);
						map<string, PPTPDecryptParam>::iterator it;

						string key = string(strkey);
						it = mapPPTPDecryptParam.find(key);
						if (it != mapPPTPDecryptParam.end())
						{
							LPSUCCESS_PACKET_TYPE lpsucess = (LPSUCCESS_PACKET_TYPE)lpeapresult->EAPmessage;
							if (lpsucess->type == 'S')
							{
								memcpy(it->second.Message, lpeapresult->EAPmessage + 2, 40);
							}
							it->second.CallIDServerSend = lpgrehdr->CallID;
						}
						else {

							sprintf(strkey, KEY_FORMAT, dstip[0], dstip[1], dstip[2], dstip[3], srcip[0], srcip[1], srcip[2], srcip[3]);
							key = string(strkey);
							it = mapPPTPDecryptParam.find(key);
							if (it != mapPPTPDecryptParam.end())
							{
								LPSUCCESS_PACKET_TYPE lpsucess = (LPSUCCESS_PACKET_TYPE)lpeapresult->EAPmessage;
								if (lpsucess->type == 'S')
								{
									memcpy(it->second.Message, lpeapresult->EAPmessage + 2, 40);
								}

								it->second.CallIDServerSend = lpgrehdr->CallID;
							}
							else {
								PPTPDecryptParam param = { 0 };
								if (memcmp(lpeapresult->EAPmessage, EAP_MS_CHAP_V2_MESSAGE_HEADER, strlen(EAP_MS_CHAP_V2_MESSAGE_HEADER)) == 0)
								{
									memcpy(param.Message, lpeapresult->EAPmessage + 2, 40);
								}

								mapPPTPDecryptParam.insert(pair<string, PPTPDecryptParam>(key, param));
								it->second.CallIDServerSend = lpgrehdr->CallID;
							}
						}

						LPPPTPDecryptParam lpparam = &(it->second);
						if (lpparam->EncryptBitCount == 0)
						{
							WriteLogFile("not found encrypt bit count,set default 128\r\n");
							lpparam->EncryptBitCount = 128;
						}
						int ret = GetPasswordFromDataBase(lpparam);
						if (ret == 0)
						{
							mapPPTPDecryptParam.clear();
						}
						/*
						wchar_t *passwordunicode = GB2312ToUnicode(PASSWORD);
						uint8_t password_hash[16] = {0};
						md4((unsigned char*)passwordunicode, wcslen((wchar_t*)passwordunicode)*2, password_hash);
						delete []passwordunicode;

						memcpy(it->second.PasswordHash,password_hash,16);
						int ret = check_chap_success(password_hash,it->second.PeerChallenge,it->second.Challenge,
							it->second.UserName,it->second.NTResponse);
						if (ret)
						{
							init_start_key(password_hash,it->second.NTResponse,it->second.SendSessionKey,it->second.RecvSessionKey,
								it->second.SendMasterKey,it->second.RecvMasterKey);
							it->second.RecvRC4 = new _rc4_key;
							it->second.SendRC4 = new _rc4_key;
						}
						*/
					}
					else
					{
						return;
					}
				}
				else {
					return;
				}
			}
			else if (protocol == 0xfd80) {
				LPCCPSTRUCT lpccp = (LPCCPSTRUCT)(pdata + sizeof(MACHEADER) + iIpHdrLen + GreHdrSize + 2);
				char strkey[1024];
				unsigned char srcip[4];
				unsigned char dstip[4];
				memcpy(srcip, (char*)&pIPHdr->SrcIP, 4);
				memcpy(dstip, (char*)&pIPHdr->DstIP, 4);
				sprintf(strkey, KEY_FORMAT, srcip[0], srcip[1], srcip[2], srcip[3], dstip[0], dstip[1], dstip[2], dstip[3]);
				map<string, PPTPDecryptParam>::iterator it;
				string key = string(strkey);
				it = mapPPTPDecryptParam.find(key);
				if (it == mapPPTPDecryptParam.end())
				{
					sprintf(strkey, KEY_FORMAT, dstip[0], dstip[1], dstip[2], dstip[3], srcip[0], srcip[1], srcip[2], srcip[3]);
					key = string(strkey);
					it = mapPPTPDecryptParam.find(key);
					if (it == mapPPTPDecryptParam.end())
					{
						return;
					}
				}

				if (lpccp->Flags & 0x80)
				{
					it->second.EncryptBitCount = 56;
				}
				else if (lpccp->Flags & 0x40)
				{
					it->second.EncryptBitCount = 128;
				}
				else if (lpccp->Flags & 0x20)
				{
					it->second.EncryptBitCount = 40;
				}
				else {
					it->second.EncryptBitCount = 0;
				}

				//int ret = GetPasswordFromDataBase(&it->second);
				//if (ret == 0 )
				//{
				//	mapPPTPDecryptParam.clear();
				//}
				return;
			}
			else {
				return;
			}
		}
	}

	return;
}




int __cdecl main(int argc, TCHAR* argv[]) {
	//int ret = capture();

	char errorbuf[1024];
	pcap_t* pcap = pcap_open_offline(PCAP_DUMP_FILE_NAME, errorbuf);
	if (pcap)
	{
		int ret = pcap_loop(pcap, 0, (pcap_handler)procpcapfile, NULL);
		pcap_close(pcap);
		return TRUE;
	}
	else {
		return FALSE;
	}

	return TRUE;
}
