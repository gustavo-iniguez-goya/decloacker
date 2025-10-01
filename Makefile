
prepare:
	@mkdir -p bin/

ebpf:
	@cd pkg/ebpf/kern/ && make

decloacker:
	CGO_ENABLED=0 go build -o bin/decloacker

all: prepare ebpf decloacker

clean:
	rm -f bin/decloacker
	@cd pkg/ebpf/kern && make clean

.DEFAULT_GOAL := all
