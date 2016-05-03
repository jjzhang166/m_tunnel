
CC=gcc
CFLAGS= -g -Wall -std=c99 -lc -Wdeprecated-declarations

SRCS := $(shell find src -name "*.c")
DIRS := $(shell find src -type d)

INCS := $(foreach n, $(DIRS), -I$(n))

all: sock5.out

sock5.out: $(SRCS)
	$(CC) $(CFLAGS) $(INCS) -o $@ $^ -DTEST_TUNNEL_LOCAL -DMNET_BUF_SIZE=262144

clean:
	rm -rf *.out *.dSYM
