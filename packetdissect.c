#include "packetdissect.h"

/* this file is for pasing packet */

void dump_packet(FILE *fs, u_char *tcpdata, u_int32_t len)
{
	int i,j,k=0; 
	int max_bound=0;
	//printf("\n");
	for ( k = 0; k < len ; k+=16 )
	{
		if ( ( (len-k) / 16) > 0) 
		{
			max_bound = 16;
		} else {
			max_bound = len % 16;
		}
		for ( i = 0; i < max_bound; i++ )
		{
			fprintf(fs, "%02x ", tcpdata[k+i]);			
		}		
		if ( max_bound < 16) 
		{
			for ( i = 0; i < 16-max_bound; i++) 
			{
				fprintf(fs, "   ");
			}
		}
		for ( j = 0; j < max_bound; j++) 
		{		
		    if ( tcpdata[k+j] < 127 &&  tcpdata[k+j] > 32 ) 
			{
			    fprintf(fs,"%c", tcpdata[k+j]);
			} else {
				fprintf(fs, ".");
			}
		}
		fprintf (fs, "<br />\n");			  
	}
	fprintf (fs, "<br />\n");
}

/* Based on code from http://en.wikipedia.org/wiki/Endianness */
int isBigEndian()
{
   long int i = 1;
   const char *p = (const char *) &i;
   if (p[0] == 1)  // Lowest address contains the least significant byte
      return 0;
   else
      return 1;
}

int isIPaddrMatch(ipv4addr_t srcIPaddr, ipv4addr_t dstIPaddr)
{
	if ( srcIPaddr.addrQ1 == dstIPaddr.addrQ1 && 
		 srcIPaddr.addrQ2 == dstIPaddr.addrQ2 && 
		 srcIPaddr.addrQ3 == dstIPaddr.addrQ3 && 
		 srcIPaddr.addrQ4 == dstIPaddr.addrQ4 )
	{
		return 1;
	} else {
	    return 0;
	}
}

int isPortNumberinList(u_int16_t Ports[], u_int numPortsinlist, u_int16_t pnum )
{
	u_int i; 
	if ( pnum < WELL_KNOWN_PORTS)
	{
		return -1;
	}
	for (i = 0; i < numPortsinlist; i++)
	{
		if ((Ports[i] == pnum) )
		{
			return i;
		}
	}
	return -1;
}

void addPortNumberintoList(u_int16_t Ports[], u_int numPortsinlist, u_int16_t pnum)
{
	Ports[numPortsinlist] = pnum;		
}

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
void unpack_packet(const u_char* origIpPacket, packet_struct_t* parsedPacket, size_t capturedSize) 
{
	unsigned int ipOptsLen = 0;

	/* extract IP version */
    parsedPacket->ipVer = origIpPacket[0]>>4;    
	/* extract IP header length */
    parsedPacket->ipHdrLen = origIpPacket[0]&0x0f;
	/* extract Type of Service */
    parsedPacket->tos = origIpPacket[1];
	/* extract Total length */
    parsedPacket->packetLen = htons(*((u_int16_t*)(origIpPacket+2)));
	/* extract Identification */
    parsedPacket->id = htons(*((u_int16_t*)(origIpPacket+4))); 
	/* extract Flags & Fragment Offset */
    if (isBigEndian()) {
        parsedPacket->flags = origIpPacket[6]>>5;
        parsedPacket->fragOffset = (*((u_int16_t*)(origIpPacket+6)))&0x1fff;
    } else {
        parsedPacket->flags = origIpPacket[6]&0x07;
        parsedPacket->fragOffset = (*((u_int16_t*)(origIpPacket+6)))&0xf8ff;
    }
	/* extract Time to Live */
    memcpy(&(parsedPacket->ttl), origIpPacket+8, 12);
    parsedPacket->ipOpts = 0;
    if (parsedPacket->ipHdrLen>5) {
        ipOptsLen = 4 * ((parsedPacket->ipHdrLen)-5);
        parsedPacket->ipOpts = malloc( ipOptsLen );
        memcpy(parsedPacket->ipOpts, origIpPacket+20, ipOptsLen);
    }
}

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

void unpack_tcppacket(const u_char* origtcpPacket, tcppacket_struct_t* parsedTCPPacket, size_t capturedSize) 
{
	    unsigned int tcpOptsLen = 0; 
	    parsedTCPPacket->srcPort = htons(*((u_int16_t*)(origtcpPacket))); 
        parsedTCPPacket->dstPort = htons(*((u_int16_t*)(origtcpPacket+2))); 
        parsedTCPPacket->seqNum = htonl(*((u_int32_t*)(origtcpPacket+4))); 
        parsedTCPPacket->ackNum = htonl(*((u_int32_t*)(origtcpPacket+8))); 
        parsedTCPPacket->tcpHdrLen = *(origtcpPacket+12)>>4;
        parsedTCPPacket->urg = *(origtcpPacket+13)&0x20;
        parsedTCPPacket->ack = *(origtcpPacket+13)&0x10;
        parsedTCPPacket->psh = *(origtcpPacket+13)&0x08;
        parsedTCPPacket->rst = *(origtcpPacket+13)&0x04;
        parsedTCPPacket->syn = *(origtcpPacket+13)&0x02;
        parsedTCPPacket->fin = *(origtcpPacket+13)&0x01;
        parsedTCPPacket->tcpWindow = htons(*((u_int16_t*)(origtcpPacket+14)));
        parsedTCPPacket->xsum = htons(*((u_int16_t*)(origtcpPacket+16))); 
        parsedTCPPacket->urgPtr = htons(*((u_int16_t*)(origtcpPacket+18)));
        parsedTCPPacket->tcpOpts = 0;       
        if (parsedTCPPacket->tcpHdrLen>5) {
            tcpOptsLen = 4 * ((parsedTCPPacket->tcpHdrLen)-5);
            parsedTCPPacket->tcpOpts = malloc( tcpOptsLen );
            memcpy(parsedTCPPacket->tcpOpts, origtcpPacket+20, tcpOptsLen);
        }
}

