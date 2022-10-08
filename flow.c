#include "argparse.h"

int main(int argc, char **argv)
{
    int opt;
    int timer = 60;
    int interval = 10;
    int count = 1024;
    FILE *file = stdin;
    char *collector = "127.0.0.1:2055";
    char *ptr = NULL;
    while ((opt = getopt(argc, argv, "f:c:a:i:m:")) != -1)
    {
        if(arg_parse(&opt, &timer, &interval, &count, file, collector, ptr)) {
            return 1;
        }
    }
    if (file != stdin)
    {
        fclose(file);
    }
    return 0;
}