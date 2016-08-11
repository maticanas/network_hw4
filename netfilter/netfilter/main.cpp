/*
* netfilter.c
* (C) 2013, all rights reserved,
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
* DESCRIPTION:
* This is a simple traffic filter/firewall using WinDivert.
*
* usage: netfilter.exe windivert-filter [priority]
*
* Any traffic that matches the windivert-filter will be blocked using one of
* the following methods:
* - TCP: send a TCP RST to the packet's source.
* - UDP: send a ICMP(v6) "destination unreachable" to the packet's source.
* - ICMP/ICMPv6: Drop the packet.
*
* This program is similar to Linux's iptables with the "-j REJECT" target.
*/

#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "windivert.h"

#include <conio.h>

#define MAXBUF  0xFFFF
#define MAXFILTERLEN 100
#define ETEHR_HEADER_LEN 14
#define MAXURL_LEN 1000
#define MAXMALSITENUM 100000 

///////////
enum protocol {
	ipv4, ipv6, tcp
};

unsigned int protocol_number[] = { 0x0800, 0x86DD, 0x06 }; //not right

char * protocol_string[] = { "ipv4", "ipv6", "tcp" };

unsigned int offset = 0;

struct ether_addr
{
	unsigned char ether_addr_octet[6];
};

struct ether_header
{
	struct  ether_addr ether_dhost;
	struct  ether_addr ether_shost;
	unsigned short ether_type;
};

struct ip_header
{
	unsigned char ip_header_len : 4;
	unsigned char ip_version : 4;
	unsigned char ip_tos;
	unsigned short ip_total_length;
	unsigned short ip_id;
	unsigned char ip_frag_offset : 5;
	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;
	unsigned char ip_frag_offset1;
	unsigned char ip_ttl;
	unsigned char ip_protocol;
	unsigned short ip_checksum;
	struct in_addr ip_srcaddr;
	struct in_addr ip_destaddr;
};

struct tcp_header
{
	unsigned short source_port;
	unsigned short dest_port;
	unsigned int sequence;
	unsigned int acknowledge;
	unsigned char ns : 1;
	unsigned char reserved_part1 : 3;
	unsigned char data_offset : 4;
	unsigned char fin : 1;
	unsigned char syn : 1;
	unsigned char rst : 1;
	unsigned char psh : 1;
	unsigned char ack : 1;
	unsigned char urg : 1;
	unsigned char ecn : 1;
	unsigned char cwr : 1;
	unsigned short window;
	unsigned short checksum;
	unsigned short urgent_pointer;
};

struct malsite
{
	char url[MAXURL_LEN];
	//unsigned long long Hash;
};

int get_mal_site(struct malsite * ms, FILE *fp)
{
	int msnum = 0;

	while (!feof(fp))
	{
		fscanf(fp, "%s\n", ms[msnum].url);
		printf("%s\n", ms[msnum].url);
		msnum++;
	}
	return msnum;
}

bool filter_mal_site(char HTTP_url[MAXURL_LEN], struct malsite * ms, int msnum)
{
	int idx;
	for (idx = 0; idx < msnum; idx++)
	{
		if (!strstr(HTTP_url, ms[idx].url))
		{
			printf("malsite blocked : %s\n", HTTP_url);
			return true;
		}
	}
	return false;
}




bool ipv4filter_L4(struct ip_header *ih, protocol p)
{
	if (protocol_number[p] != ih->ip_protocol)
	{
		//printf("not %s\n", protocol_string[p]);
		return 0;
	}
	return 1;
}

bool filter_L3(struct ether_header *eh, protocol p)
{
	unsigned short ether_type = ntohs(eh->ether_type);
	//eh->ether_type = ether_type;
	if (ether_type != protocol_number[p])
	{
		//printf("%x", ether_type);
		//printf("not %s protocol   ", protocol_string[p]);
		return 0;
	}
	return 1;
}

bool filter_tcp(unsigned char packet[MAXBUF], struct tcp_header ** th)
{
	struct ether_header *eh;
	struct ip_header *ih;
	eh = (struct ether_header *)packet;
	//if (filter_L3(eh, ipv4))
	//{
		//ih = (struct ip_header *)(packet + ETEHR_HEADER_LEN);
		ih = (struct ip_header *)(packet);
		if (ipv4filter_L4(ih, tcp))
		{
			//printf("it's tcp packet\n");
			*th = (struct tcp_header *)(((unsigned char *)ih)+ (ih->ip_header_len * 4));
			return 1;
		}
	//}
	return 0;
}
/*
unsigned char * find_HTTP(unsigned char packet[MAXBUF], unsigned char *http_header)
{
	unsigned char * search;
	for (search = http_header; search < packet + sizeof(packet); search++)
	{
		(unsigned char *)strstr((const char *)http_header, "HTTP/1.1");
	}
	return NULL;
}
*/
bool filter_http(unsigned char packet[MAXBUF], struct malsite *ms, int msnum)
{
	struct tcp_header * th;
	unsigned char * http_header;
	unsigned char * HTTP_loc;
	unsigned char * HTTP_end_loc;
	unsigned char * HTTP_url_loc;
	unsigned char * HTTP_url_end_loc;
	char HTTP_url[MAXURL_LEN] = {0,};
	int url_len = 0;

	if (!filter_tcp(packet, &th))
	{
		//printf("not tcp");
		return 0;
	}
	http_header = (unsigned char *)th + (th->data_offset * 4);
	HTTP_loc = (unsigned char *)strstr((const char *)http_header, "HTTP/1.1");
	if (HTTP_loc == NULL)
		HTTP_loc = (unsigned char *)strstr((const char *)http_header, "HTTP/1.0");

	if (HTTP_loc == NULL)
	{
		//printf("not http\n");
		return false;
	}
	//printf("http packet =>");

	HTTP_end_loc = (unsigned char *)strstr((const char *)http_header, "\n\n");
	HTTP_url_loc = (unsigned char *)strstr((const char *)http_header, "Host: ") + 6;

	if (HTTP_url_loc == (unsigned char *)6)
	{
		//printf("cannot find url\n");
		return false;
	}

	HTTP_url_end_loc = (unsigned char *)strstr((const char *)HTTP_url_loc, "\n") - 1; //1 0d 0a에서 0a의 위치를 주기 때문에 1 뺌 
	url_len = (int)((int)HTTP_url_end_loc - (int)HTTP_url_loc);
	memcpy((char *)HTTP_url, (char *)HTTP_url_loc, url_len);
	HTTP_url[url_len] = '\0';

	printf("url : %s\n", HTTP_url);

	if (filter_mal_site(HTTP_url, ms, msnum))
		return true;
	else
		return false;
}




/*
* Entry.
*/
int __cdecl main(int argc, char **argv)
{
	FILE *fp;
	HANDLE handle, console;
	UINT i;
	INT16 priority = 0;
	unsigned char packet[MAXBUF];
	UINT packet_len;
	WINDIVERT_ADDRESS recv_addr, send_addr;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;
	UINT payload_len;

	fp = fopen("mal_site.txt", "r");
	//filter and priority set
	char filter[MAXFILTERLEN] = "ip.DstAddr == 192.168.32.14 or ip.SrcAddr == 192.168.32.14";
	priority = 0;

	struct malsite * ms;
	int msnum;

	ms = (struct malsite *)malloc(sizeof(malsite)*MAXMALSITENUM);
	msnum = get_mal_site(ms, fp);
	


	// Divert traffic matching the filter:
	handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, priority, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
		{
			fprintf(stderr, "error: filter syntax error\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}

	// Main loop:
	while (TRUE)
	{
		// Read a matching packet.
		// drop if it is null
		if (!WinDivertRecv(handle, packet, sizeof(packet), &recv_addr,
			&packet_len))
		{
			fprintf(stderr, "warning: failed to read packet\n");
			continue;
		}

		if (filter_http(packet, ms, msnum))
		{
			printf("malsite detected\n");
			continue;
		}


		if (!WinDivertSend(handle, packet, packet_len, &recv_addr, NULL)) {
			printf("Send Error\n");
		}
		
	}

	free(ms);
	fclose(fp);

		
}

