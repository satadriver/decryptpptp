#ifndef _PUBLICTYPE_H_
#define _PUBLICTYPE_H_

//#include <inttypes.h>
#pragma pack(1)

typedef unsigned long DWORD;
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef  unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;



#define GREMINHDRLEN 8
#define GREPROTOPPP 0x880b
#define GRESYNSETFLAG 0x0010
#define GREACKSETFLAG 0x8000

#define PPPPROTOCHAP 0xc223
#define PPPPROTOCCP 0x80fd
#define PPPPROTOLCP 0xc021
#define PPPPROTOCOMP 0x00fd
#define PPPPROTOCOMP_ 0xfd
#define PPPPROTOIP 0x0021
#define PPPPROTOIP_ 0x21
#define PPPUSERNAMEOFFSET 54

#define MAX_NT_PASSWORD 256
#define MD4_SIGNATURE_SIZE    16

/*
 * Max # bytes for a CCP option
 */

#define CCP_MAX_OPTION_LENGTH	32


/*
 * Definitions for MPPE/MPPC.
 */

#define CI_MPPE			18	/* config option for MPPE */
#define CILEN_MPPE		6	/* length of config option */

#define MPPE_OVHD		4	/* MPPE overhead */
#define MPPE_MAX_KEY_LEN	16	/* largest key length (128-bit) */

#define MPPE_STATELESS          0x01	/* configuration bit H */
#define MPPE_40BIT              0x20	/* configuration bit L */
#define MPPE_56BIT              0x80	/* configuration bit M */
#define MPPE_128BIT             0x40	/* configuration bit S */
#define MPPE_MPPC               0x01	/* configuration bit C */

#define MPPE_BIT_FLUSHED	0x80	/* bit A */
#define MPPE_BIT_RESET		0x40	/* bit B */
#define MPPE_BIT_COMP		0x20	/* bit C */
#define MPPE_BIT_ENCRYPTED	0x10	/* bit D */

#define MPPE_SALT0		0xD1	/* values used in MPPE key derivation */
#define MPPE_SALT1		0x26	/* according to RFC3079 */
#define MPPE_SALT2		0x9E

#define MPPE_HIST_LEN		8192	/* MPPC history size */
#define MPPE_MAX_CCOUNT		0x0FFF	/* max. coherency counter value */

#define MPPE_MAX_KEY_LEN	16	/* largest key length (128-bit) */
#define DECOMP_ERROR		-1	/* error detected before decomp. */
#define DECOMP_FATALERROR	-2	/* error detected after decomp. */

/*
 * The basic PPP frame.
 */
#define PPP_HDRLEN	4	/* octets for standard ppp header */
#define PPP_FCSLEN	2	/* octets for FCS */
#define PPP_MRU		1500	/* default MRU = max length of info field */

#define MPPE_CCOUNT(x)		((((x)[0] & 0x0f) << 8) + (x)[1])
#define MPPE_BITS(x)		((x)[0] & 0xf0)

#define ex16be(px)  (*((unsigned char*)(px)+0)<< 8 | *((unsigned char*)(px)+1)<< 0)
#define ex32be(px)  (*((unsigned char*)(px)+0)<<24 | *((unsigned char*)(px)+1)<<16 | *((unsigned char*)(px)+2)<< 8 | *((unsigned char*)(px)+3)<< 0)




/* 4 bytes IP address */
typedef struct 
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
} ip_address;

typedef struct 
{
	unsigned version;
	unsigned header_length;
	unsigned total_length;
	unsigned fragment_length;
	unsigned tos;
	unsigned id;
	unsigned flags;
	unsigned fragment_offset;
	unsigned ttl;
	unsigned protocol;
	unsigned checksum;
	unsigned src_ip;
	unsigned dst_ip;
} ip_h;

typedef struct  
{
	unsigned src_port;
	unsigned dst_port;
	unsigned seqno;
	unsigned ackno;
	unsigned header_length;
	unsigned flags;
	unsigned window;
	unsigned checksum;
	unsigned urgent;
} tcp;


/* IPv4 header */
typedef struct 
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	uint32_t	saddr;		// Source address
	uint32_t	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
}  ip_header;

struct tcp_header
{
	uint16_t src;
	uint16_t dst;
	uint32_t seq;
	uint32_t ack;

	uint8_t x2:4;
	uint8_t off:4;

	uint8_t flg;			/* flag1 | flag2 */
	uint16_t win;
	uint16_t sum;
	uint16_t urp;
} ;

/* UDP header*/
typedef struct 
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}  udp_header;

struct pptp_header
{
	uint16_t length;	  /* message length in octets, including header */
	uint16_t pptp_type;	  /* PPTP message type. 1 for control message.  */
	uint32_t magic;		  /* this should be PPTP_MAGIC.                 */
	uint16_t ctrl_type;	  /* Control message type (0-15)                */
	uint16_t reserved0;	  /* reserved.  MUST BE ZERO.                   */
	union
	{
		struct
		{
			uint16_t call_id;
			uint16_t peer_call_id;
		} call_id;
		char c[1];		
	};
} ;



typedef struct 
{
	uint16_t   flags;
	uint16_t   type;
	uint16_t   length;
	uint16_t   callid;
	uint16_t   seq; /* optional based on flags */
	uint16_t   ack; /* optional based on flags */
}  gre_header;

typedef struct 
{
	uint16_t   proto;
}  ppp_header;

typedef struct 
{
	uint8_t    code;
	uint8_t    identifier;
	uint16_t   length;
	union {
		struct {
			uint8_t    datalen;
			uint8_t    authchal[16];
		} chaldata;
		struct {
			uint8_t    datalen;
			uint8_t    peerchal[16];
			uint8_t    unknown[8]; /* all zero's */
			uint8_t    peerresp[24];
			uint8_t    state;
			uint8_t    *name;
		} respdata;
	} u;
}  pppchap_header;

typedef struct 
{
	// options
	uint8_t	   type;
	uint8_t	   option_length;
	union
	{
		char micro_data[4];	// Microsoft PPE/PPC, type = 18
		char data[1];		// others
	} u;
}  ccp_header_sub1;

typedef struct 
{
	uint8_t    code;
	uint8_t    identifier;
	uint16_t   length;
	union
	{
		ccp_header_sub1 sub1;
		char data[1];
	} b;
	// options
//	uint8_t	   type;
//	uint8_t	   option_length;
//	union
//	{
//		char micro_data[4];	// Microsoft PPE/PPC, type = 18
//		char data[1];		// others
//	} u;
	
}  ccp_header;

typedef struct 
{
	uint8_t flag;
	uint8_t count;
	char data[1];
}  mppe_header;

typedef struct 
{
	uint8_t code;
}  lcp_header;

typedef struct 
{      
	unsigned char state[256];       
	unsigned char x;        
	unsigned char y;
}  _rc4_key;

typedef struct  
{
	uint32_t unc_bytes;		/* total uncompressed bytes */
	uint32_t unc_packets;	/* total uncompressed packets */
	uint32_t comp_bytes;	/* compressed bytes */
	uint32_t comp_packets;	/* compressed packets */
	uint32_t inc_bytes;		/* incompressible bytes */
	uint32_t inc_packets;	/* incompressible packets */
	/* the compression ratio is defined as in_count / bytes_out */
	uint32_t in_count;		/* Bytes received */
	uint32_t bytes_out;		/* Bytes transmitted */
	double	ratio;			/* not computed in kernel. */
}  compstat;

typedef struct 
{
	struct pcap_pkthdr *header;
	u_char * pkt_data;
} queue_data;

typedef void (*pcap_handler_ex)(u_char *, const struct pcap_pkthdr *, const u_char *, void *);

struct hashpass_rec 
{
	unsigned char rec_size;
	char *password;
	unsigned char hash[16];
} ;

/* Structure for the index file from genkeys */
struct hashpassidx_rec 
{
	unsigned char hashkey[2];
	long offset;
	unsigned long long int 	numrec;
} ;

#endif
