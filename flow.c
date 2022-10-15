#include "argparse.h"
/* GLOBAL VARIABLES BECAUSE OF PCAP_LOOP*/
packet_item *ptr;
packet_item *head;
int timer_g;
int interval_g;

/*
 * dissect/print packet
 */
packet_item *exists(packet_item *item)
{
    packet_item *tmp;
    tmp = head;
    while (tmp != NULL)
    {
        // printf("%s %s\n", tmp->data->sourceIP, item->data->sourceIP);
        if (strcmp(tmp->data->sourceIP, item->data->sourceIP) != 0)
        {
            tmp = tmp->next;
            continue;
        }
        if (strcmp(tmp->data->destinationIP, item->data->destinationIP) != 0)
        {
            tmp = tmp->next;
            continue;
        }
        if (tmp->data->sourcePORT != item->data->sourcePORT)
        {
            tmp = tmp->next;
            continue;
        }
        if (tmp->data->destinationPORT != item->data->destinationPORT)
        {
            tmp = tmp->next;
            continue;
        }
        if (strcmp(tmp->data->Protocol_type, item->data->Protocol_type) != 0)
        {
            tmp = tmp->next;
            continue;
        }
        return tmp;
    }
    return NULL;
}

void pcap_handle(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    const struct sniff_ip *ip;   /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const struct sniff_udp *udp; /* The UDP header */
    packet_item *new_item = malloc(sizeof(packet_item));
    new_item->data = malloc(sizeof(packet_struct));
    packet_item *tmp = NULL;
    int SourcePort = 0;
    int DestPort = 0;
    char *type = NULL;
    int time = header->ts.tv_sec;

    // time
    struct tm ts;
    char buf[80];

    (void)args;

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
        SourcePort = ntohs(tcp->th_sport);
        DestPort = ntohs(tcp->th_dport);
        type = "TCP";
        break;
    case IPPROTO_UDP:
        printf("   Protocol: UDP\n");
        udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + size_ip);
        printf("    Source port: %d\n", ntohs(udp->udp_sport));
        printf("    Destination port: %d\n", ntohs(udp->udp_dport));
        SourcePort = ntohs(udp->udp_sport);
        DestPort = ntohs(udp->udp_dport);
        type = "UDP";
        break;
    case IPPROTO_ICMP:
        printf("   Protocol: ICMP\n");
        type = "ICMP";
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
    printf("\n");

    new_item->data->sourceIP = malloc(strlen(inet_ntoa(ip->ip_src)));
    new_item->data->destinationIP = malloc(strlen(inet_ntoa(ip->ip_dst)));
    new_item->data->sourceIP = memcpy(new_item->data->sourceIP, inet_ntoa(ip->ip_src), strlen(inet_ntoa(ip->ip_src)));
    new_item->data->sourceIP[strlen(inet_ntoa(ip->ip_src))] = '\0';
    new_item->data->destinationIP = memcpy(new_item->data->destinationIP, inet_ntoa(ip->ip_dst), strlen(inet_ntoa(ip->ip_dst)));
    new_item->data->destinationIP[strlen(inet_ntoa(ip->ip_dst))] = '\0';
    new_item->data->sourcePORT = SourcePort;
    new_item->data->destinationPORT = DestPort;
    new_item->data->Protocol_type = type;
    new_item->data->time = time;
    new_item->data->firstTime = time;
    new_item->data->size = htons(ip->ip_len);
    if (!head)
    {
        head = new_item;
        head->next = NULL;
        ptr = head;
    }
    else
    {
        tmp = exists(new_item);
        if (tmp == NULL)
        {
            ptr->next = new_item;
            ptr = ptr->next;
            ptr->next = NULL;
        }
        else
        {
            tmp->data->time = new_item->data->time;
            tmp->data->size += htons(ip->ip_len);
        }
    }
    // printf("%s %s %d %d %s %d\n", new_item->data->sourceIP, new_item->data->destinationIP, new_item->data->sourcePORT, new_item->data->destinationPORT, new_item->data->Protocol_type, new_item->data->time);
    // free(new_item->data->sourceIP);
    // free(new_item->data->destinationIP);
    // free(new_item->data);
    // free(new_item);
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
    timer_g = timer;
    interval_g = interval;
    if (device_set(file))
    {
        return 1;
    }
    packet_item *tmp;
    tmp = head;
    while (tmp != NULL)
    {
        printf("%s:%d %s:%d %s %d %d %d\n", tmp->data->sourceIP, tmp->data->sourcePORT, tmp->data->destinationIP, tmp->data->destinationPORT, tmp->data->Protocol_type, tmp->data->time, tmp->data->firstTime, tmp->data->size);
        tmp = tmp->next;
    }
    //  struct hostent *host_entry = gethostbyname(collector);
    //  char *IPbuffer = inet_ntoa(*((struct in_addr *)host_entry->h_addr_list[0]));
    //  printf("%s\n", IPbuffer);
    return 0;
}