
CC=gcc
CFLAGS= -g -Wall -std=c99 -Wdeprecated-declarations
LIBS= -lpthread -lc

SRCS := $(shell find src -name "*.c")
DIRS := $(shell find src -type d)

INCS := $(foreach n, $(DIRS), -I$(n))

all: tun_local.out tun_remote.out

tun_local.out: $(SRCS)
	$(CC) $(CFLAGS) $(INCS) -o $@ $^ $(LIBS) -DTEST_TUNNEL_LOCAL

tun_remote.out: $(SRCS)
	$(CC) $(CFLAGS) $(INCS) -o $@ $^ $(LIBS) -DTEST_TUNNEL_REMOTE

clean:
	rm -rf *.out *.dSYM
