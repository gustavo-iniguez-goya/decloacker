
SRC := $(wildcard *.c)
BIN := $(SRC:.c=.o)

#iter_tasks:
#	clang -O2 -g -target bpf -c dump_tasks.c -o dump_tasks.o -I/usr/include -I/usr/include/bpf

%.o: %.c
	 clang -O2 -g -target bpf -c $*.c -o $*.o -I/usr/include -I/usr/include/bpf

all: $(BIN)

clean:
	rm -f $(BIN)

.PHONY: all
