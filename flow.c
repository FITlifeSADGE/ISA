#include "argparse.h"

/*void hostname_ip(char **collector)
{
    int contains_char = 0;
    char *IPbuffer = NULL;
    for (size_t i = 0; i < strlen(*collector); i++)
    {
        if (isalpha(*collector[i]))
        {
            contains_char = 1;
            break;
        }
        else
        {
            continue;
        }
    }
    if (!contains_char)
    {
        return;
    }
    struct hostent *host_entry = gethostbyname(*collector);
    if ((IPbuffer = inet_ntoa(*((struct in_addr *)host_entry->h_addr_list[0]))))
    {
        *collector = IPbuffer;
    }
    else
    {
        exit(1);
    }
}*/

/*
 * dissect/print packet
 */
void pcap_handle(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    const struct sniff_ip *ip;   /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const struct sniff_udp *udp; /* The UDP header */

    // time
    struct tm ts;
    char buf[80];

    (void)args;
    (void)header;

    int size_ip;

    /* define/compute ip header offset */
    ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;

    /* print source and destination IP addresses */
    printf("   From: %s\n", inet_ntoa(ip->ip_src));
    printf("   To: %s\n", inet_ntoa(ip->ip_dst));

    /* ToS print */
    printf("   ToS: %d\n", ip->ip_tos);

    /* determine protocol */
    switch (ip->ip_p)
    {
    case IPPROTO_TCP:
        printf("   Protocol: TCP\n");
        tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
        printf("   Src port: %d\n", ntohs(tcp->th_sport));
        printf("   Dst port: %d\n", ntohs(tcp->th_dport));
        break;
    case IPPROTO_UDP:
        printf("   Protocol: UDP\n");
        udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + size_ip);
        printf("    Source port: %d\n", ntohs(udp->udp_sport));
        printf("    Destination port: %d\n", ntohs(udp->udp_dport));
        break;
    case IPPROTO_ICMP:
        printf("   Protocol: ICMP\n");
        break;
    default:
        printf("   Protocol: unknown\n");
        return;
    }


    // time print
    printf("   Time: %ld\n", header->ts.tv_sec);
    ts = *localtime(&header->ts.tv_sec);
    strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S %Z", &ts);
    printf("   Time: %s\n", buf);
    return;
}

int device_set(char *file)
{
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char filter[] = "ip";
    bpf_u_int32 net = 0;
    struct bpf_program fp;
    if (strcmp(file, "stdin") == 0)
    {
        if (!(handle = pcap_open_offline("-", errbuff)))
        {
            fprintf(stderr, "Error in reading from STDIN, for reading: %s\n", errbuff);
            return 1;
        }
    }
    else
    {
        if (!(handle = pcap_open_offline(file, errbuff)))
        {
            fprintf(stderr, "Error in opening savefile, %s, for reading: %s\n", file, errbuff);
            return 1;
        }
    }
    if (pcap_compile(handle, &fp, filter, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    pcap_loop(handle, 10000, pcap_handle, NULL);
    pcap_freecode(&fp);
    pcap_close(handle);
    printf("success\n");
    return 0;
}

int main(int argc, char **argv)
{
    extern int opterr;
    opterr = 0;
    int opt;
    int timer = 60;
    int interval = 10;
    int count = 1024;
    char *file = "stdin";
    char *collector = "127.0.0.1:2055";
    char *ptr = NULL;
    while ((opt = getopt(argc, argv, ":f:c:a:i:m:")) != -1)
    {
        if (arg_parse(&opt, &timer, &interval, &count, &file, &collector, ptr))
        {
            return 1;
        }
    }
    if (device_set(file))
    {
        return 1;
    }
    // struct hostent *host_entry = gethostbyname(collector);
    // char *IPbuffer = inet_ntoa(*((struct in_addr *)host_entry->h_addr_list[0]));
    // printf("%s\n", IPbuffer);
    return 0;
}