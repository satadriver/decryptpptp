

#include <windows.h>

#define PCAP_OPENFLAG_PROMISCUOUS			1
#define PCAP_OPEN_LIVE_TO_MS_VALUE_NEGTIVE -1
#define PCAP_OPEN_LIVE_TO_MS_VALUE_0		0
#define WINPCAP_MAX_BUFFER_SIZE				100*0x100000
#define WSASTARTUP_VERSION					0x0202
#define MAX_PACKET_SIZE						0x10000
#define GRE_PACKET_FILTER					"gre"
#define PCAP_DUMP_FILE_NAME					"tmp.pcap"

int __stdcall capture();