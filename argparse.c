#include "argparse.h"
/*Function arg_parse parses arguments and stores values in variables*/
int arg_parse(int *opt, int *timer, int *interval, int *count, char **file, char **collector, char *ptr) {
    switch (*opt)
        {
        case 'f':
            *file = optarg;
            break;
        case 'c':
            *collector = optarg;
            break;
        case 'a':
            *timer = strtol(optarg, &ptr, 10);
            if (*timer <= 0)
            {
                return 1;
            }
            break;
        case 'i':
            *interval = strtol(optarg, &ptr, 10);
            if (*interval <= 0)
            {
                return 1;
            }
            break;
        case 'm':
            *count = strtol(optarg, &ptr, 10);
            if (*count <= 0)
            {
                return 1;
            }
            break;
        case '?':
            printf("unknown parameter %c, please use only -f -c -a -i -m\n", optopt);
            return 1;
        case ':':
            printf("value needed for parameter %c\n", optopt);
            return 1;
        }
        return 0;
}