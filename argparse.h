#ifndef __ARGPARSE_H__
#define __ARGPARSE_H__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>

int arg_parse(int *opt, int *timer, int *interval, int *count, FILE *file, char *collector, char *ptr);

#endif