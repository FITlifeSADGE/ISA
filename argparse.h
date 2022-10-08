#ifndef __ARGPARSE_H__
#define __ARGPARSE_H__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>

typedef struct {
    char *sourceIP;
    char *destinationIP;
    char *sourcePORT;
    char *destinationPORT;
}packet_struct;

typedef struct packet_item{
    packet_struct *data;
    struct packet_item *next;
}packet_item;

int arg_parse(int *opt, int *timer, int *interval, int *count, char **file, char **collector, char *ptr);

#endif