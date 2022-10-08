CC = gcc
CFLAGS = -O2 -std=c99 -pedantic -Wall -Wextra -g -lm
LOGIN = xkapra00

all: flow


flow: flow.o argparse.o
	$(CC) $(CFLAGS) $^ -o $@

flow.o: flow.c argparse.h
	$(CC) $(CFLAGS) -c $<

argparse.o: argparse.c argparse.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o flow

zip:
	zip $(LOGIN).zip *.c *.h Makefile