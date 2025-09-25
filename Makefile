
prepare:
	mkdir -p bin/

decloacker:
	CGO_ENABLED=0 go build -o bin/decloacker

all: prepare decloacker

clean:
	rm -f bin/decloacker

.PHONY: all
