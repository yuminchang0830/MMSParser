#ifndef __PACKETDISSECT_H__
#define __PACKETDISSECT_H__

#include "packetstructure.h"

int isBigEndian();  /* check packet is bigendian or little endian */
int isIPaddrMatch(ipv4addr_t srcIPaddr, ipv4addr_t dstIPaddr);   /* compare IP adress, if match, return 1 */
int isPortNumberinList(u_int16_t Ports[], u_int numPortsinlist, u_int16_t pnum ); /* check port number whether in port list*/
void dump_packet(FILE *fs, u_char *tcpdata, u_int32_t len);  /* dump tcp packet data content*/
void addPortNumberintoList(u_int16_t Ports[], u_int numPortsinlist, u_int16_t pnum); /* add port number into port list */
void unpack_packet(const u_char* origIpPacket, packet_struct_t* parsedPacket, size_t capturedSize); /* dissect IP packet */
void unpack_tcppacket(const u_char* origtcpPacket, tcppacket_struct_t* parsedTCPPacket, size_t capturedSize); /* dissect TCP packet */

#endif  /*__PACKETDISSECT_H__ */