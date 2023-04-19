#ifndef PACKET_H_H_H
#define PACKET_H_H_H



#include <windows.h>

#define MAC_ADDRESS_SIZE 6

#pragma pack(1)





typedef struct {
	unsigned char type;
	unsigned char equalflag;
	unsigned char authstring[40];
}SUCCESS_PACKET_TYPE, * LPSUCCESS_PACKET_TYPE;


typedef struct
{
	unsigned char			DstMAC[MAC_ADDRESS_SIZE];
	unsigned char			SrcMAC[MAC_ADDRESS_SIZE];
	unsigned short			Protocol;
}MACHEADER, * LPMACHEADER;



typedef struct {
	unsigned short Flags;
	unsigned short ProtocolType;
	unsigned short PayloadLen;
	unsigned short CallID;
	unsigned int SeqNO;
}GREHEADER, * LPGREHEADER;



typedef struct {
	unsigned short Flags;
	unsigned short ProtocolType;
	unsigned short PayloadLen;
	unsigned short CallID;
	unsigned int SeqNO;
	unsigned int AckNO;
}GREACKHEADER, * LPGREACKHEADER;


typedef struct {
	unsigned char Code;
	unsigned char Id;
	unsigned short Length;
	unsigned char Type;
	unsigned char EAPopcode;
	unsigned char EAPid;
	unsigned short EAPlength;
	unsigned char EAPvaluelen;
	unsigned char EAPchallenge[16];
	unsigned char* EAPname[64];
}EAPCHALLENGE, * LPEAPCHALLENGE;



typedef struct {
	unsigned char Code;
	unsigned char Id;
	unsigned short Length;
	unsigned char Type;
	unsigned char EAPopcode;
	unsigned char EAPid;
	unsigned short EAPlength;
	unsigned char EAPvaluelen;
	unsigned char EAPpeerchallenge[16];
	unsigned char EAPreserved[8];
	unsigned char EAPntresponse[24];
	unsigned char EAPusernamesplit;
	unsigned char EAPusername[64];
}EAPRESPONSE, * LPEAPRESPONSE;


typedef struct {
	unsigned char Code;
	unsigned char Id;
	unsigned short Length;
	unsigned char Type;
	unsigned char EAPopcode;
	unsigned char EAPid;
	unsigned short EAPlength;
	//unsigned char EAPvaluelen;
	unsigned char EAPmessage[40];
}EAPRESULT, * LPEAPRESULT;


typedef struct {
	unsigned char Code;
	unsigned char Identifier;
	unsigned short Length;
	unsigned char OptionType;
	unsigned char OptionLength;
	unsigned char Unused[3];
	unsigned char Flags;
}CCPSTRUCT, * LPCCPSTRUCT;


typedef struct {

	unsigned char packetnohigh : 4;
	unsigned char isencrypted : 1;
	unsigned char iscompress : 1;
	unsigned char unused2 : 1;
	unsigned char unused : 1;
	unsigned char packetnolow;
}PPTPDATAHDR, * LPPPTPDATAHDR;


typedef struct
{
	unsigned char			HeaderSize : 4;		//uint is 4 bytes
	unsigned char			Version : 4;			//watch for sequence! bit feild allocate from high bit

	unsigned char			Undefined : 1;
	unsigned char			Cost : 1;
	unsigned char			Reliability : 1;
	unsigned char			Throughout : 1;
	unsigned char			Delay : 1;
	unsigned char			Priority : 3;

	unsigned short			PacketSize;			// ip packet total lenth,net sequence
	unsigned short			PacketID;			// packet ID

	unsigned short			FragmentOffset : 13;	//分片偏移，以8字节为单位，unit is 8 byte
	unsigned short			MF : 1;				//MF=1,后面还有分片；MF=0,最后一个分片
	unsigned short			DF : 1;				//DF=1,不允许分片；DF=0,可以分片
	unsigned short			Unnamed : 1;

	unsigned char			TimeToLive;			// ip packet time to live in the network
	unsigned char			Protocol;			// 6= tcp,11=udp,1=icmp,2=igmp
	unsigned short			HeaderChksum;		// ip header checksum,not total packet checksum as tcp!
	unsigned int			SrcIP;				// source ip
	unsigned int			DstIP;				// destination ip
}IPHEADER, * LPIPHEADER;


typedef struct
{
	unsigned short			SrcPort;			// source port 
	unsigned short			DstPort;			// destination port
	unsigned int 			SeqNum;				// sequence number
	unsigned int 			AckNum;				// acknowledge number

	unsigned short			Reserved : 4;
	unsigned short			HeaderSize : 4;		// tcp header size,uint is 4 byte! not byte!

	unsigned short			CWR : 1;
	unsigned short			ECN_ECHO : 1;
	unsigned short			FIN : 1;
	unsigned short			SYN : 1;
	unsigned short			RST : 1;
	unsigned short			PSH : 1;
	unsigned short			ACK : 1;
	unsigned short			URG : 1;

	unsigned short			WindowSize;			// window size in communication,general is 64240 bytes
	unsigned short			PacketChksum;		// tcp total packet checksum,not checksum of only header as ip!
	unsigned short			UrgentPtr;			// urgent pointer
} TCPHEADER, * LPTCPHEADER;

typedef struct
{
	unsigned short			SrcPort;			//SrcPort
	unsigned short			DstPort;			//DstPort
	unsigned short			PacketSize;			//packet Lenth,including header and content
	unsigned short			PacketChksum;		//udp total packet checksum,like tcp,but do not like ip packet!
} UDPHEADER, * LPUDPHEADER;

typedef struct
{
	unsigned short TransactionID;		//交易ID，发出和接收必须相同
	unsigned short Flags;				//标志字段，发出和接收都应该修改该字段
	unsigned short Questions;			//问题格式
	unsigned short AnswerRRS;			//回答资源记录个数
	unsigned short AuthorityRRS;		//认证资源记录个数
	unsigned short AdditionalRRS;		//附加资源记录个数
}DNSHEADER, * LPDNSHEADER;

//中间的要解析的名称以一个非可打印字符开头，以0结尾，后面紧跟着解析的类型要求，和CLASS要求
typedef struct
{
	unsigned short	Name;				//名称，低字节为从开头的偏移地址，只想要解析的内容
	unsigned short	Type;				//类型，0005为解析字符串，0001为解析IP地址
	unsigned short 	Class;				//输入
	unsigned short	HighTTL;			//生存周期
	unsigned short	LowTTL;
	unsigned short	AddrLen;			//解析的长度
	unsigned int	Address;			//解析的内容
}DNSANSWER, * LPDNSANSWER;




typedef struct
{
	DWORD dwSrcIP;
	DWORD dwDstIP;
	USHORT Protocol;
	USHORT UdpLen;
}UDPFAKEHEADER, * LPUDPFAKEHEADER;

#endif