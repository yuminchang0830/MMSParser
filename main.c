#include <stdio.h>
#include <string.h> /* For memcpy(3) */
#include <pcap.h>
#include <stdlib.h> /* For malloc(3), free(3) */
#include <Winsock2.h>

#include "packetstructure.h"
#include "packetdissect.h"

#define MAX_NUM_PORT_IN_FILE 100
#define MAX_TRANSMIT_TIME 300 /* MMS timeout value */
#define TIME_SCALE 10  /* 10 sec a slot*/
#define MAX_TIME_RANGE (MAX_TRANSMIT_TIME/TIME_SCALE) /* 1 slot per 10 sec */

typedef struct
{
	u_int16_t Ports[MAX_NUM_PORT_IN_FILE]; 
	long startTime[MAX_NUM_PORT_IN_FILE];
	long endTime[MAX_NUM_PORT_IN_FILE];
	u_int32_t MaxL[MAX_NUM_PORT_IN_FILE];
	u_int32_t SrcL[MAX_NUM_PORT_IN_FILE][MAX_TIME_RANGE];
	u_int32_t DstL[MAX_NUM_PORT_IN_FILE][MAX_TIME_RANGE];
	int numPortsinlist;
} port_list ;

int main(int argc, char **argv)
{
	pcap_t *fp;   /* PCAP file */
	pcap_dumper_t *dumpfile;  /* output pcap file */
	char errbuf[PCAP_ERRBUF_SIZE]; 
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	u_int i=0,j=0;	
	int res;
	packet_struct_t parsedPacket;
	tcppacket_struct_t parsedTCPPacket;
	/* MMS server address default value is 10.0.0.172 */
	ipv4addr_t MMS_SERVER_ADDR = {10,0,0,172};	
	FILE *fPtr;  
	port_list plist;

	int temp_port_index=0;
	plist.numPortsinlist = 0;

	/* initialize port list */
	memset(&plist, 0, sizeof(plist));

	
	if(argc != 2)
	{	
		printf("usage: %s filename", argv[0]);
		return -1;

	}

	/* Open the capture file */
	if ((fp = pcap_open_offline(argv[1],			// name of the device
						 errbuf					// error buffer
						 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the file %s.\n", argv[1]);
		return -1;
	}	   

	///* Open the dump file */
	dumpfile = pcap_dump_open(fp, "ExpertInfo.pcap");
	printf("open output file done\n");

	/* Open the output file */
	fPtr = fopen("parsedresult.html", "w");
	if (!fPtr)
	{
        printf("Open Fail\n");   
		return 0;
    }


	/* Write HTML5 header */
	fprintf(fPtr, "<!DOCTYPE HTML><html>\n");
	fprintf(fPtr, "<head><title> MMS parsed Result<\/title><\/head>\n");	
	fprintf(fPtr, "<body>\n");
				

	
	/* Retrieve the packets from the file */
	while((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		//printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);					
		unpack_packet(pkt_data, &parsedPacket, header->caplen );
		
		if ( isIPaddrMatch(MMS_SERVER_ADDR, parsedPacket.dstIPaddr) || isIPaddrMatch(MMS_SERVER_ADDR, parsedPacket.srcIPaddr))
		{				
			if (parsedPacket.protocol == IPH_TCP_PROTOCOL) 
		    {
				/* parser TCP packet */
				unpack_tcppacket(pkt_data+20, &parsedTCPPacket, (4 * ((parsedPacket.ipHdrLen)-5)));
				//printf("unpacket tcppacket is done\n");

				if (parsedTCPPacket.syn > 0) 
				{
					pcap_dump(dumpfile, header, pkt_data);
					fprintf(fPtr, "<p> <time>%02d:%02d:%02d.%06d</time>", ltoh(header->ts.tv_sec), ltom(header->ts.tv_sec), ltos(header->ts.tv_sec), header->ts.tv_usec);
					fprintf(fPtr, "[SYN");
					if ( parsedTCPPacket.ack > 0 )
					{
						fprintf(fPtr, ", ACK],");
					} else {
						fprintf(fPtr, "],     ");
					}
					fprintf(fPtr, "TCP.srcPort=%5d, TCP.dstPort=%5d</p>\n", parsedTCPPacket.srcPort, parsedTCPPacket.dstPort);				 
			    } else if ( parsedTCPPacket.fin > 0 )
				{
					pcap_dump(dumpfile, header, pkt_data);
					fprintf(fPtr, "<p> <time>%02d:%02d:%02d.%06d</time>", ltoh(header->ts.tv_sec), ltom(header->ts.tv_sec), ltos(header->ts.tv_sec), header->ts.tv_usec);
					fprintf(fPtr, "[FIN");
					if ( parsedTCPPacket.ack > 0 )
					{
						fprintf(fPtr, ", ACK],");
					} else {
						fprintf(fPtr, "],     ");
					}

					fprintf(fPtr, "TCP.srcPort=%05d, TCP.dstPort=%5d</p>\n", parsedTCPPacket.srcPort, parsedTCPPacket.dstPort);
		        }  else if ( parsedTCPPacket.rst > 0)
				{
					pcap_dump(dumpfile, header, pkt_data);
					fprintf(fPtr, "<p> <time>%02d:%02d:%02d.%06d</time>", ltoh(header->ts.tv_sec), ltom(header->ts.tv_sec), ltos(header->ts.tv_sec), header->ts.tv_usec);
					fprintf(fPtr, "[RST");
					if ( parsedTCPPacket.ack > 0 )
					{
						fprintf(fPtr, ", ACK],");
					} else {
						fprintf(fPtr, "],     ");
					}
					fprintf(fPtr, "TCP.srcPort=%05d, TCP.dstPort=%5d</p>\n", parsedTCPPacket.srcPort, parsedTCPPacket.dstPort);
	            }

				if (header->len > (20+(parsedTCPPacket.tcpHdrLen*4)))	
				{
					if ( strncmp( pkt_data+20+ (parsedTCPPacket.tcpHdrLen*4), "HTTP", 4) == 0)
					{
					   pcap_dump(dumpfile, header, pkt_data);
					  fprintf(fPtr, "<form> <fieldset>\n");
					  fprintf(fPtr, " <legend>\n");
					  fprintf(fPtr, "<time>%02d:%02d:%02d.%06d</time> HTTP </legend>\n", ltoh(header->ts.tv_sec), ltom(header->ts.tv_sec), ltos(header->ts.tv_sec), header->ts.tv_usec);				
					  dump_packet (fPtr, pkt_data+ (20+(parsedTCPPacket.tcpHdrLen*4))  , header->len -  (20+(parsedTCPPacket.tcpHdrLen*4)));  					  					
					  fprintf(fPtr, "</fieldset></form> \n");
				    } else if (strncmp (pkt_data+20+(parsedTCPPacket.tcpHdrLen*4), "GET", 3) == 0)
				    {
					   pcap_dump(dumpfile, header, pkt_data);
                       fprintf(fPtr, "<form> <fieldset>\n");
					   fprintf(fPtr, " <legend>\n");
					   fprintf(fPtr, "<time>%02d:%02d:%02d.%06d</time> GET </legend>\n", ltoh(header->ts.tv_sec), ltom(header->ts.tv_sec), ltos(header->ts.tv_sec), header->ts.tv_usec);				
					   dump_packet (fPtr, pkt_data+ (20+(parsedTCPPacket.tcpHdrLen*4))  , header->len -  (20+(parsedTCPPacket.tcpHdrLen*4)));  
					   fprintf(fPtr, "</fieldset></form> \n");
				    } else if (strncmp( pkt_data+20+(parsedTCPPacket.tcpHdrLen*4), "POST", 4) == 0)
				    {
					   pcap_dump(dumpfile, header, pkt_data);
                       fprintf(fPtr, "<form> <fieldset>\n");
					   fprintf(fPtr, " <legend>\n");
					   fprintf(fPtr, "<time>%02d:%02d:%02d.%06d</time> POST </legend>\n", ltoh(header->ts.tv_sec), ltom(header->ts.tv_sec), ltos(header->ts.tv_sec), header->ts.tv_usec);				
					   dump_packet (fPtr, pkt_data+ (20+(parsedTCPPacket.tcpHdrLen*4))  , header->len -  (20+(parsedTCPPacket.tcpHdrLen*4)));   
					   fprintf(fPtr, "</fieldset></form> \n");
					} else {
						// printf("TCP HDR LEN=%d\n", (parsedTCPPacket.tcpHdrLen*4));
					}
				}					
					
				temp_port_index = isPortNumberinList(plist.Ports, plist.numPortsinlist, parsedTCPPacket.srcPort);
				//printf("temp_port_index = %d\n", temp_port_index);
				if ( temp_port_index < 0 && parsedTCPPacket.srcPort> WELL_KNOWN_PORTS)
				{
					//printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);	
					addPortNumberintoList(plist.Ports, plist.numPortsinlist, parsedTCPPacket.srcPort);
					plist.startTime[plist.numPortsinlist] = header->ts.tv_sec;
					plist.endTime[plist.numPortsinlist] = header->ts.tv_sec;
					//printf("%ld:%ld (%ld)\n", plist.startTime[plist.numPortsinlist], header->ts.tv_usec, header->len);	
					plist.SrcL[plist.numPortsinlist][0] = parsedPacket.packetLen;
					plist.numPortsinlist++;
				} else if (parsedTCPPacket.srcPort> WELL_KNOWN_PORTS ){
					//printf("port = %d, packet time %d is located at time range = %d\n",temp_port_index,  header->ts.tv_sec,  ((header->ts.tv_sec -  plist.startTime[temp_port_index]) /TIME_SCALE));
				
					if (  ((header->ts.tv_sec -  plist.startTime[temp_port_index]) /TIME_SCALE) < MAX_TIME_RANGE)
					{
					 plist.SrcL[temp_port_index][((header->ts.tv_sec -  plist.startTime[temp_port_index]) /TIME_SCALE)] += parsedPacket.packetLen;
					 plist.endTime[temp_port_index] = header->ts.tv_sec;
					} else {
						printf(" transmit time is outof range\n");
					}
					
				}

				temp_port_index = isPortNumberinList(plist.Ports, plist.numPortsinlist, parsedTCPPacket.dstPort);
				if ( temp_port_index < 0 && parsedTCPPacket.dstPort >  WELL_KNOWN_PORTS)
				{
					//printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);	
					addPortNumberintoList(plist.Ports, plist.numPortsinlist, parsedTCPPacket.dstPort);
					plist.startTime[plist.numPortsinlist] = header->ts.tv_sec;
					plist.endTime[plist.numPortsinlist] = header->ts.tv_sec;
					//printf("%ld:%ld (%ld)\n", plist.startTime[plist.numPortsinlist], header->ts.tv_usec, header->len);	
					plist.DstL[plist.numPortsinlist][0] = parsedPacket.packetLen;
					plist.numPortsinlist++;
				} else if ( parsedTCPPacket.dstPort> WELL_KNOWN_PORTS) {
					//printf("port = %d, packet time %d is located at time range = %d\n",temp_port_index,  header->ts.tv_sec,  ((header->ts.tv_sec -  plist.startTime[temp_port_index]) /TIME_SCALE));
					if (  ((header->ts.tv_sec -  plist.startTime[temp_port_index]) /TIME_SCALE) < MAX_TIME_RANGE)
					{
						plist.DstL[temp_port_index][((header->ts.tv_sec -  plist.startTime[temp_port_index]) /TIME_SCALE)] +=  parsedPacket.packetLen;
						plist.endTime[temp_port_index] = header->ts.tv_sec;
					} else {
						printf(" transmit time is outof range\n");
					}				
					
				}
			}
		}	
	}	

	printf("\nDump Port number\n");

	for ( i = 0; i < plist.numPortsinlist; i++)
	{
		printf(" port in list[%d] = %d, startTime = %d\n", i, plist.Ports[i],plist.startTime[i]);
		for ( j =0 ; j < MAX_TIME_RANGE; j++)
		{
			printf ("%d ", plist.DstL[i][j]);   
		}
		printf("\n");
		for ( j =0 ; j < MAX_TIME_RANGE; j++)
		{
			printf ("%d ", plist.SrcL[i][j]);   
		}
		printf("\n");
	}

	for ( i = 0; i < plist.numPortsinlist; i++)
	{	
		fprintf(fPtr,"<font size=4>MMS%d<\/font><br>\n", i+1);
		fprintf(fPtr,"<font size=3>MMS start from %02d:%02d:%02d to %02d:%02d:%02d <\/font><br>\n", ltoh(plist.startTime[i]), ltom(plist.startTime[i]), ltos(plist.startTime[i]) , ltoh(plist.endTime[i]), ltom(plist.endTime[i]), ltos(plist.endTime[i]) );
		fprintf(fPtr,"<font size=3>MMS take %d sec to tramit/receive<\/font><br>\n",  plist.endTime[i] - plist.startTime[i]);
		fprintf(fPtr, "<img src=\"https:\/\/chart.googleapis.com\/chart?");
	    fprintf(fPtr, "chxr=0,0,3000|1,300,10&chxt=x,y&chbh=a&chs=600x370&cht=bhs&chco=4D89F9,C6D9FD&chds=0,3000,0,3000&chd=t:");
		fprintf(fPtr, "%d", plist.DstL[i][0]/125);   
		for ( j =1 ; j < MAX_TIME_RANGE; j++)
		{
			fprintf(fPtr,",%d", plist.DstL[i][j]/125);   
		}
		fprintf(fPtr,"|");
		fprintf(fPtr, "%d", plist.SrcL[i][0]/125);  	
		for ( j =1 ; j < MAX_TIME_RANGE; j++)
		{
			fprintf(fPtr,",%d", plist.SrcL[i][j]/125);   
		}	
		fprintf(fPtr, "&chtt=Multi-Media Message\" width=\"600\" height=\"370\" alt=\"Multi-Media Message\" \/>");
		fprintf(fPtr,"<br><br><br>\n");
	}
	
	fprintf(fPtr, "<\/body></html>");

	//getchar();
	if (res == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(fp));
	}
	
	pcap_close(fp);
	fclose(fPtr);

	return 0;
}