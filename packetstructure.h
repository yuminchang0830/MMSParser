#ifndef __PACKETSTRUCTURE_H__
#define __PACKETSTRUCTURE_H__

#include <stdio.h>
#include <string.h> /* For memcpy(3) */
#include <pcap.h>
#include <stdlib.h> /* For malloc(3), free(3) */
#include <Winsock2.h>

#define LINE_LEN 16
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN  6

/* if port number is less than 1023, it is a well-known port (it mean it has special purpose for some AP*/
#define WELL_KNOWN_PORTS 1023

/* IP header version macro */
#define IPH_IPV4_VER 4
#define IPH_IPV6_VER 6
#define IPH_TPIX_VER 7
#define IPH_PIP_VER  8

/* IP protocol version macro */
#define IPH_ICMP_PROTOCOL  1
#define IPH_TCP_PROTOCOL 6
#define IPH_UDP_PROTOCOL 17

/* MMS server address */
#define MMS_SERVER_ADDR1 10
#define MMS_SERVER_ADDR2 0
#define MMS_SERVER_ADDR3 0
#define MMS_SERVER_ADDR4 172

/* byte reversed */
//#define htoc(A) ((((u_char)(A) & 0xf0) >> 4) | \
//(((u_char)(A) & 0x0f) << 4))

/* 16 bit  Big Endian <--> Little Endian */
#define htons(A) ((((u_int16_t)(A) & 0xff00) >> 8) | \
(((u_int16_t)(A) & 0x00ff) << 8))
/* 32 bit Big Endian <---> Little Endian */
#define htonl(A) ((((u_int32_t)(A) & 0xff000000) >> 24) | \
(((u_int32_t)(A) & 0x00ff0000) >> 8) | \
(((u_int32_t)(A) & 0x0000ff00) << 8) | \
(((u_int32_t)(A) & 0x000000ff) << 24))
#define ntohs htons
#define ntohl htohl

/* Below MACRO is to transfer time stamp to XX:XX:XX format */
/* extract seconds */
#define ltos(A) (A%60)
/* extract minutes */
#define ltom(A) ((A%3600)/60)
/* extract hours */
#define ltoh(A) ((A%86400)/3600)

/* Below is IPV4 address structure */
 
typedef struct 
{
	u_char addrQ1;
    u_char addrQ2;
    u_char addrQ3;
    u_char addrQ4;
} ipv4addr_t;

/* Below is IP packet structure */

/* From RFC 791:
    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   */

typedef struct  
{   
    /* IP Header */
    u_char ipVer;
    u_char ipHdrLen;
    u_char tos;
    u_int16_t packetLen;
    u_int16_t id;
    u_char flags;
    u_int16_t fragOffset;
    u_char ttl;
    u_char protocol;
    u_int16_t hdrXsum;
	ipv4addr_t srcIPaddr;
	ipv4addr_t dstIPaddr;    
    u_char* ipOpts;
} packet_struct_t;


/* Below is TCP packet structure */

/*
   From RFC 793:
    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   */


typedef struct 
{
	/* TCP Header */
    u_int16_t srcPort; /* Also UDP */
    u_int16_t dstPort; /* Also UDP */
    u_int32_t seqNum;
    u_int32_t ackNum;
    u_char tcpHdrLen; /* This is the number of words in the TCP portion of the header. */
    u_char urg;
    u_char ack;
    u_char psh;
    u_char rst;
    u_char syn;
    u_char fin;
    u_int16_t tcpWindow;
    u_int16_t xsum;
    u_int16_t urgPtr;
    u_char* tcpOpts;
} tcppacket_struct_t ;

#endif  /* __PACKETSTRUCTURE_H__ */
