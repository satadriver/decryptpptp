
#include <stdio.h>
#include <WINSOCK2.H>
#include <windows.h>
#include "Packet.h"
#include "include\\pcap.h"
#include "include\\pcap\\pcap.h"

#include "capture.h"

#pragma comment(lib,"lib\\wpcap.lib")
#pragma comment(lib,"ws2_32.lib")













int __stdcall GreSnifferHijack(pcap_t* pcapT)
{
	pcap_pkthdr* pHeader = 0;
	const unsigned char* pData = 0;
	pcap_dumper_t* pdump = pcap_dump_open(pcapT, PCAP_DUMP_FILE_NAME);

	while (TRUE)
	{
		int iRet = pcap_next_ex(pcapT, &pHeader, &pData);
		if (iRet <= 0)
		{
			continue;
		}

		if (pHeader->caplen >= MAX_PACKET_SIZE || pHeader->len >= MAX_PACKET_SIZE || pHeader->len != pHeader->caplen || pHeader->caplen <= 0)
		{
			continue;
		}
		int iCapLen = pHeader->caplen;
		*((char*)pData + iCapLen) = 0;

		LPMACHEADER pMac = (LPMACHEADER)pData;
		if (pMac->Protocol != 0x0008)
		{
			continue;
		}

		LPIPHEADER pIPHdr = (LPIPHEADER)(pData + sizeof(MACHEADER));
		if (pIPHdr->Version != 4)
		{
			continue;
		}

		int iIpHdrLen = pIPHdr->HeaderSize << 2;
		int iIpLen = ntohs(pIPHdr->PacketSize);
		//if ( iIpLen != iCapLen - sizeof(MACHEADER) )
		//{
		//	continue;
		//}

		if (pIPHdr->Protocol == 0x2f)
		{
			pcap_dump((unsigned char*)pdump, pHeader, pData);
		}
	}
	return TRUE;
}










int __stdcall capture()
{
	int	nRetCode = 0;

	WSADATA		stWsa = { 0 };
	nRetCode = WSAStartup(WSASTARTUP_VERSION, &stWsa);
	if (nRetCode)
	{
		printf("WSAStartup error,error code is:%d\n", GetLastError());
		nRetCode = getchar();
		return -1;
	}


	//pcap_if = pcap_if_t     pcap_t = pcap
	pcap_t* pcapMain = 0;
	pcap_if_t* pcapDevBuf = 0;
	pcap_if_t* pcapTmpDev = 0;
	int			iChooseNum = 0;
	int			iTmp = 0;
	char		strPcapErrBuf[PCAP_ERRBUF_SIZE];
	char* pszDnsConfigName = 0;

	if (pcap_findalldevs(&pcapDevBuf, strPcapErrBuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", strPcapErrBuf);
		nRetCode = getchar();
		exit(0);
	}

	printf("本机安装的网卡列表如下:\n");
	for (pcapTmpDev = pcapDevBuf; pcapTmpDev; pcapTmpDev = pcapTmpDev->next)
	{
		printf("网卡号码: %d\n网卡名称: %s\n网卡描述: %s\r\n\r\n",
			iTmp + 1, pcapTmpDev->name, pcapTmpDev->description);
		++iTmp;
	}

	if (iTmp == 0)
	{
		printf("No interfaces found! Make sure WinPcap is installed\n");
		pcap_freealldevs(pcapDevBuf);
		nRetCode = getchar();
		return -1;
	}

	nRetCode = scanf("%d\r\n", &iChooseNum);
	if (iChooseNum < 1 || iChooseNum > iTmp)
	{
		printf("Interface number out of range\n");
		pcap_freealldevs(pcapDevBuf);
		nRetCode = getchar();
		return -1;
	}

	for (pcapTmpDev = pcapDevBuf, iTmp = 0; iTmp < iChooseNum - 1; pcapTmpDev = pcapTmpDev->next, iTmp++);

	if ((pcapMain = pcap_open_live(pcapTmpDev->name, MAX_PACKET_SIZE, PCAP_OPENFLAG_PROMISCUOUS, 1, strPcapErrBuf)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", pcapTmpDev->name);
		pcap_freealldevs(pcapDevBuf);
		nRetCode = getchar();
		return -1;
	}


	nRetCode = pcap_setbuff(pcapMain, WINPCAP_MAX_BUFFER_SIZE);	//the limit buffer size of capraw is 100M
	if (nRetCode == -1)
	{
		printf("pcap_setbuff error!the limit of the buffer size is 100M,maybe it is too big!\n");
		nRetCode = getchar();
		return FALSE;
	}

#define PCAP_FILTER_MASK_VALUE 0xffffff
	bpf_program		stBpfp = { 0 };
	u_int			uiMypcapNetMask = PCAP_FILTER_MASK_VALUE;
	nRetCode = pcap_compile(pcapMain, &stBpfp, GRE_PACKET_FILTER, TRUE, uiMypcapNetMask);
	if (nRetCode < 0)
	{
		fprintf(stderr, "数据包过滤条件语法设置失败,请检查过滤条件的语法设置\n");
		pcap_freealldevs(pcapDevBuf);
		nRetCode = getchar();
		return FALSE;
	}
	nRetCode = pcap_setfilter(pcapMain, &stBpfp);
	if (nRetCode < 0)
	{
		fprintf(stderr, "数据包过滤条件设置失败\n");
		pcap_freealldevs(pcapDevBuf);
		nRetCode = getchar();
		return FALSE;
	}


	printf("DNSATTACK正在监听网卡:%s\n", pcapTmpDev->description);
	pcap_freealldevs(pcapDevBuf);

	nRetCode = GreSnifferHijack(pcapMain);

	return nRetCode;
}
