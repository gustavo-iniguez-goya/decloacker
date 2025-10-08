
SRC := $(wildcard *.c)
BIN := $(SRC:.c=.o)

all: $(BIN) legacy

%.o: %.c
	clang -O2 -g -target bpf -c $*.c -o $*.o -I/usr/include -I/usr/include/bpf

# generate modules without bpf_d_path() for < 6.x kernels.
legacy:
	sed -i "s/#define WITH_PATH/\/\/#define WITH_PATH/" common.h
	clang -O2 -g -target bpf -c dump_tasks.c -o dump_tasks_5x.o -I/usr/include -I/usr/include/bpf
	sed -i "s/\/\/#define WITH_PATH/#define WITH_PATH/" common.h

clean:
	rm -f $(BIN)

.PHONY: all
