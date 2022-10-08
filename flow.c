#include "argparse.h"
#include <pcap.h>

int device_set(char *file)
{
    char errbuff[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    pcap_t *handle;
    struct pcap_pkthdr header;
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
    packet = pcap_next(handle, &header);
    printf("Jacked a packet with length of %d\n", header.len);
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
    return 0;
}