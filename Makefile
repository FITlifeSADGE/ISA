CC = gcc
CFLAGS = -O2 -std=c99 -pedantic -Wall -Wextra -g -lm -D_BSD_SOURCE -D_DEFAULT_SOURCE
LOGIN = xkapra00

all: flow


flow: flow.o argparse.o
	$(CC) $(CFLAGS) $^ -o $@ -lpcap

%.o: %.c argparse.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o flow

zip:
	zip $(LOGIN).zip *.c *.h Makefile