#include "argparse.h"

int arg_parse(int *opt, int *timer, int *interval, int *count, FILE *file, char *collector, char *ptr) {
    switch (*opt)
        {
        case 'f':
            file = fopen(optarg, "r");
            if (file == NULL)
            {
                return 1;
            }
            break;
        case 'c':
            collector = optarg;
            printf("%s\n", collector);
            break;
        case 'a':
            *timer = strtol(optarg, &ptr, 10);
            if (*timer <= 0)
            {
                return 1;
            }
            printf("timer: %d\n", *timer);
            break;
        case 'i':
            *interval = strtol(optarg, &ptr, 10);
            if (*interval <= 0)
            {
                return 1;
            }
            printf("interval: %d\n", *interval);
            break;
        case 'm':
            *count = strtol(optarg, &ptr, 10);
            if (*count <= 0)
            {
                return 1;
            }
            printf("count: %d\n", *count);
            break;
        default:
            printf("unknown parameter, please use only -f -c -a -i -m\n");
            return 1;
        }
        return 0;
}