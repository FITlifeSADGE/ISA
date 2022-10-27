#ifndef __ARGPARSE_H__
#define __ARGPARSE_H__

#include <pcap.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include<err.h>

typedef struct
{
	char *sourceIP;
	char *destinationIP;
	int sourcePORT;
	int destinationPORT;
	char *Protocol_type;
	int time;
	int firstTime;
	int size;
	int ToS;
	int packet_count;
	int dOctets;
	int flags;
} packet_struct;

typedef struct packet_item
{
	packet_struct *data;
	struct packet_item *next;
} packet_item;

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6

#define SIZE_ETHERNET 14

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* Ethernet header */
struct sniff_ethernet
{
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type;					/* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip
{
	u_char ip_vhl;				   /* version << 4 | header length >> 2 */
	u_char ip_tos;				   /* type of service */
	u_short ip_len;				   /* total length */
	u_short ip_id;				   /* identification */
	u_short ip_off;				   /* fragment offset field */
#define IP_RF 0x8000			   /* reserved fragment flag */
#define IP_DF 0x4000			   /* don't fragment flag */
#define IP_MF 0x2000			   /* more fragments flag */
#define IP_OFFMASK 0x1fff		   /* mask for fragmenting bits */
	u_char ip_ttl;				   /* time to live */
	u_char ip_p;				   /* protocol */
	u_short ip_sum;				   /* checksum */
	struct in_addr ip_src, ip_dst; /* source and dest address */
};

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp
{
	u_short th_sport; /* source port */
	u_short th_dport; /* destination port */
	tcp_seq th_seq;	  /* sequence number */
	tcp_seq th_ack;	  /* acknowledgement number */
	u_char th_offx2;  /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) > 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
	u_short th_win; /* window */
	u_short th_sum; /* checksum */
	u_short th_urp; /* urgent pointer */
};

struct sniff_udp
{
	u_short udp_sport;	  /* source port */
	u_short udp_dport;	  /* destination port */
	u_short udp_length;	  /* total length */
	u_short udp_checksum; /* checksum */
	u_int test;
};

typedef struct export
{
	u_short version;
	u_short count;
	u_int SysUptime;
	u_int unix_secs;
	u_int unix_nsecs;
	u_int flow_sequence;
	u_char engine_type;
	u_char engine_id;
	u_short sampling_interval;

	struct in_addr srcaddr;
	struct in_addr dstaddr;
	u_int nexthop;
	u_short input;
	u_short output;
	u_int dPkts;
	u_int dOctets;
	u_int First;
	u_int Last;
	u_short srcport;
	u_short dstport;
	u_char pad1;
	u_char tcp_flags;
	u_char prot;
	u_char tos;
	u_short src_as;
	u_short dst_as;
	u_char src_mask;
	u_char dst_mask;
	u_short pad2;
}
export;

typedef struct global {
	int timer_g;
	int interval_g;
	int count_g;

	int first_time;
	int last_time;
	int flow_count;
	int flows_total;
}global;

int arg_parse(int *opt, int *timer, int *interval, int *count, char **file, char **collector, char *ptr);

#endif