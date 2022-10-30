#include "argparse.h"
/* GLOBAL VARIABLES BECAUSE OF PCAP_LOOP*/
packet_item *ptr;
packet_item *head;

global glob_vars;
packet_item *exists(packet_item *item);

void swap(packet_item *a, packet_item *b)
{
    packet_struct *temp = a->data;
    a->data = b->data;
    b->data = temp;
}

void bubbleSort(packet_item *start)
{
    int swapped;
    packet_item *ptr1;
    packet_item *lptr = NULL;

    /* Checking for empty list */
    if (start == NULL)
        return;

    do
    {
        swapped = 0;
        ptr1 = start;

        while (ptr1->next != lptr)
        {
            if (ptr1->data->time > ptr1->next->data->time)
            {
                swap(ptr1, ptr1->next);
                swapped = 1;
            }
            ptr1 = ptr1->next;
        }
        lptr = ptr1;
    } while (swapped);
}
export export_item(packet_item *tmp)
{
    export export_t;
    export_t.version = 5;
    export_t.count = 1;
    export_t.SysUptime = time(NULL) - tmp->data->firstTime;
    export_t.unix_secs = time(NULL);
    export_t.unix_nsecs = time(NULL) * 1000000;     // přepsat
    export_t.flow_sequence = glob_vars.flows_total; // možná pořadí odeslaného flow? ještě kontrola
    export_t.engine_type = 0;
    export_t.engine_id = 0;
    export_t.sampling_interval = 0;

    inet_aton(tmp->data->sourceIP, &(export_t.srcaddr));
    inet_aton(tmp->data->destinationIP, &(export_t.dstaddr));
    export_t.nexthop = 0;
    export_t.input = 0;
    export_t.output = 0;
    export_t.dPkts = tmp->data->packet_count;
    export_t.dOctets = tmp->data->dOctets;
    export_t.First = tmp->data->firstTime;
    export_t.Last = tmp->data->time;
    export_t.srcport = tmp->data->sourcePORT;
    export_t.dstport = tmp->data->destinationPORT;
    export_t.pad1 = 0;
    export_t.tcp_flags = tmp->data->flags;
    if (strcmp(tmp->data->Protocol_type, "ICMP") == 0)
    {
        export_t.prot = IPPROTO_ICMP;
    }
    if (strcmp(tmp->data->Protocol_type, "TCP") == 0)
    {
        export_t.prot = IPPROTO_TCP;
    }
    if (strcmp(tmp->data->Protocol_type, "UDP") == 0)
    {
        export_t.prot = IPPROTO_UDP;
    }
    export_t.tos = tmp->data->ToS;
    export_t.src_as = 0;
    export_t.dst_as = 0;
    export_t.src_mask = 32;
    export_t.dst_mask = 32;
    export_t.pad2 = 0;
    return export_t;
}

void send_packets()
{
    packet_item *tmp = head;
    packet_item *pointer = tmp;
    export export_t;
    int sock;                        // socket descriptor
    int msg_size, i;
    struct sockaddr_in server; // address structures of the server and the client
    struct hostent *servent;         // network host entry required by gethostbyname()    
    char buffer[sizeof(struct export)];            
   
    memset(&server,0,sizeof(server)); // erase the server structure
    server.sin_family = AF_INET;                   

    // make DNS resolution of the first parameter using gethostbyname()
    msg_size = sizeof(struct export);

    /*přepsat*/
    if ((servent = gethostbyname(glob_vars.col_IP)) == NULL) // check the first parameter
        errx(1,"gethostbyname() failed\n");

    // copy the first parameter to the server.sin_addr structure
    memcpy(&server.sin_addr,servent->h_addr,servent->h_length); 

    /* Přepsat*/
    server.sin_port = htons(atoi(glob_vars.col_PORT));        // server port (network byte order)
    
    if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1)   //create a client socket
        err(1,"socket() failed\n");
    
    //printf("* Server socket created\n");
        

    //printf("* Creating a connected UDP socket using connect()\n");                
    // create a connected UDP socket
    if (connect(sock, (struct sockaddr *)&server, sizeof(server))  == -1)
        err(1, "connect() failed");
    while (tmp != NULL)
    {
        export_t = export_item(tmp);
        memcpy(buffer, &export_t, sizeof(tmp));
        printf("%s:%d %s:%d %s %d %d %d SENT\n", tmp->data->sourceIP, tmp->data->sourcePORT, tmp->data->destinationIP, tmp->data->destinationPORT, tmp->data->Protocol_type, tmp->data->time, tmp->data->firstTime, tmp->data->size);
        tmp = tmp->next;
        free(pointer->data->sourceIP);
        free(pointer->data->destinationIP);
        free(pointer->data);
        free(pointer);
        pointer = tmp;
    }
    i = send(sock,buffer,msg_size,0);     // send data to the server
    if (i == -1)                   // check if data was sent correctly
        err(1,"send() failed");
    else if (i != msg_size)
        err(1,"send(): buffer written partially");
    if (msg_size == -1)
        err(1,"reading failed");
    close(sock);
    //printf("* Closing the client socket ...\n");
}

void send_packet()
{
    export export_t;
    packet_item *tmp = head;
    int sock;                        // socket descriptor
    int msg_size, i;
    struct sockaddr_in server; // address structures of the server and the client
    struct hostent *servent;         // network host entry required by gethostbyname()     
    char buffer[sizeof(export)];            
   
    memset(&server,0,sizeof(server)); // erase the server structure
    server.sin_family = AF_INET;                   

    msg_size = sizeof(struct export);
    // make DNS resolution of the first parameter using gethostbyname()


    /*přepsat*/
    if ((servent = gethostbyname(glob_vars.col_IP)) == NULL) // check the first parameter
        errx(1,"gethostbyname() failed\n");

    // copy the first parameter to the server.sin_addr structure
    memcpy(&server.sin_addr,servent->h_addr,servent->h_length); 

    /* Přepsat*/
    server.sin_port = htons(atoi(glob_vars.col_PORT));        // server port (network byte order)
    
    if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1)   //create a client socket
        err(1,"socket() failed\n");
    
    //printf("* Server socket created\n");
        

    //printf("* Creating a connected UDP socket using connect()\n");                
    // create a connected UDP socket
    if (connect(sock, (struct sockaddr *)&server, sizeof(server))  == -1)
        err(1, "connect() failed");
    export_t = export_item(tmp);
    memcpy(buffer, &export_t, sizeof(tmp));
    printf("%s:%d %s:%d %s %d %d %d SENT\n", tmp->data->sourceIP, tmp->data->sourcePORT, tmp->data->destinationIP, tmp->data->destinationPORT, tmp->data->Protocol_type, tmp->data->time, tmp->data->firstTime, tmp->data->size);
    free(tmp->data->sourceIP);
    free(tmp->data->destinationIP);
    free(tmp->data);
    free(tmp);
    i = send(sock,buffer,msg_size,0);     // send data to the server
    if (i == -1)                   // check if data was sent correctly
    err(1,"send() failed");
    else if (i != msg_size)
    err(1,"send(): buffer written partially");
    if (msg_size == -1)
    err(1,"reading failed");
    close(sock);
    //printf("* Closing the client socket ...\n");
}

/*
 * checks, whether time between first and last packet of a flow exceeded timer, or time between the latest and newest packet exceeded interval time
 */
/* Přidat možnost kontroly více podmínek najednou, možná hotovo, ještě testovat*/
int timer_check(int timer, int interval, int *first, int *last, int *flows, packet_item *item, int *head_del)
{
    packet_item *head_next = NULL;
    // inactive
    if (((item->data->time - head->data->time) >= interval))
    {
        bubbleSort(head);
        //printf("interval exceeded, flow exported\n");
        while ((item->data->time - head->data->time) >= interval)
        {
            head_next = head->next;
            send_packet();
            *flows -= 1;
            head = head_next;
            if (!head)
            {
                break;
            }
        }
        if (!head)
        {
            *head_del = 1;
            head = item;
            head->next = NULL;
        }
        *first = head->data->time;
        // testovat, jestli to funguje dobře
        timer_check(timer, interval, first, last, flows, item, head_del);
        return 1;
    }
    head_next = exists(item);
    if ((*flows == glob_vars.count_g) && (head_next == NULL))
    {
        //printf("flow count exceeded, flow exported\n");
        head_next = head->next;
        send_packet();
        head = head_next;
        if (!head)
        {
            *head_del = 1;
            head = item;
            head->next = NULL;
        }
        *first = head->data->time;
        *flows -= 1;
        // testovat, jestli to funguje dobře
        timer_check(timer, interval, first, last, flows, item, head_del);
        return 1;
    }
    if (*first == 0)
    {
        *first = item->data->time;
    }
    *last = item->data->time;
    // active
    if ((*last - *first) >= timer)
    {
        //printf("timer exceeded, flow exported\n");
        while ((*last - *first) >= timer)
        {
            head_next = head->next;
            send_packet();
            *flows -= 1;
            head = head_next;
            if (!head)
            {
                break;
            }
        }
        if (!head)
        {
            *head_del = 1;
            head = item;
            head->next = NULL;
        }
        *first = head->data->time;
        // testovat, jestli to funguje dobře
        timer_check(timer, interval, first, last, flows, item, head_del);
        return 1;
    }
    return 0;
}

packet_item *exists(packet_item *item)
{
    packet_item *tmp;
    tmp = head;
    while (tmp != NULL)
    {
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
/*
 * dissect/print packet
 */
void pcap_handle(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    const struct sniff_ip *ip;   /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const struct sniff_udp *udp; /* The UDP header */
    packet_item *new_item = malloc(sizeof(packet_item));
    new_item->data = malloc(sizeof(packet_struct));
    packet_item *tmp = NULL;
    int head_del = 0;

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

    /* determine protocol */
    switch (ip->ip_p)
    {
    case IPPROTO_TCP:
        tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
        SourcePort = ntohs(tcp->th_sport);
        DestPort = ntohs(tcp->th_dport);
        type = "TCP";
        new_item->data->flags = tcp->th_flags;
        break;
    case IPPROTO_UDP:
        udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + size_ip);
        SourcePort = ntohs(udp->udp_sport);
        DestPort = ntohs(udp->udp_dport);
        type = "UDP";
        new_item->data->flags = 0;
        break;
    case IPPROTO_ICMP:
        type = "ICMP";
        new_item->data->flags = 0;
        break;
    default:
        printf("   Protocol: unknown\n");
        return;
    }

    ts = *localtime(&header->ts.tv_sec);
    strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S %Z", &ts);

    new_item->data->sourceIP = malloc(strlen(inet_ntoa(ip->ip_src)) + 1);
    new_item->data->destinationIP = malloc(strlen(inet_ntoa(ip->ip_dst)) + 1);
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
    new_item->data->ToS = ip->ip_tos;
    new_item->data->packet_count = 1;
    new_item->data->dOctets = ntohl((u_int32_t)(header->caplen - SIZE_ETHERNET));
    if (!head)
    {
        head = new_item;
        ptr = head;
        head->next = NULL;
        glob_vars.flow_count = 1;
        glob_vars.flows_total = 1;
    }
    else
    {
        if (timer_check(glob_vars.timer_g, glob_vars.interval_g, &(glob_vars.first_time), &(glob_vars.last_time), &(glob_vars.flow_count), new_item, &head_del))
        {
            if (head_del)
            {
                ptr = head;
                return;
            }
        }
        tmp = exists(new_item);
        if (tmp == NULL)
        {
            ptr->next = new_item;
            ptr = ptr->next;
            ptr->next = NULL;
            glob_vars.flow_count += 1;
            glob_vars.flows_total += 1;
        }
        else
        {
            tmp->data->time = new_item->data->time;
            tmp->data->size += htons(ip->ip_len);
            tmp->data->packet_count += 1;
            tmp->data->dOctets += ntohl((u_int32_t)(header->caplen - SIZE_ETHERNET));
            tmp->data->flags = (tmp->data->flags | new_item->data->flags);
            free(new_item->data->sourceIP);
            free(new_item->data->destinationIP);
            free(new_item->data);
            free(new_item);
        }
    }
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
    //printf("success\n");
    if (head)
    {
        bubbleSort(head);
        send_packets();
    }
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
    char hostname[100];
    char *point = NULL;
    char *char_ptr;
    char *char1_ptr;
    char *IPbuffer;
    char *port_num = "0";
    while ((opt = getopt(argc, argv, ":f:c:a:i:m:")) != -1)
    {
        if (arg_parse(&opt, &timer, &interval, &count, &file, &collector, point))
        {
            return 1;
        }
    }
    glob_vars.timer_g = timer;
    glob_vars.interval_g = interval;
    glob_vars.count_g = count;

    memcpy(hostname, collector, strlen(collector));
    hostname[strlen(collector)] = '\0';
    char_ptr = strrchr(hostname, ':');
    char1_ptr = strrchr(hostname, '/');
    if (!char_ptr) {
        struct hostent *host_entry = gethostbyname(hostname);
        IPbuffer = inet_ntoa(*((struct in_addr *)host_entry->h_addr_list[0]));
    }
    else {
        if (char1_ptr) {
            //memmove(char1_ptr, char1_ptr+1, strlen(char1_ptr));
            for(int i = 0; hostname[i] != *char1_ptr; i++) {
                memmove(hostname, hostname+1, strlen(hostname));
            }
            memmove(hostname, hostname+1, strlen(hostname));
            char_ptr = strrchr(hostname, ':');
        }
        if (char_ptr) {
            memmove(char_ptr, char_ptr+1, strlen(char_ptr));
            port_num = strdup(char_ptr);
            *char_ptr = 0;
            struct hostent *host_entry = gethostbyname(hostname);
            IPbuffer = inet_ntoa(*((struct in_addr *)host_entry->h_addr_list[0]));
        }
        else {
            struct hostent *host_entry = gethostbyname(hostname);
            IPbuffer = inet_ntoa(*((struct in_addr *)host_entry->h_addr_list[0]));
        }
    }
    glob_vars.col_IP = strdup(IPbuffer);
    glob_vars.col_PORT = strdup(port_num);

    if (device_set(file))
    {
        return 1;
    }
    return 0;
}