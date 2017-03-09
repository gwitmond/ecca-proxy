# Makefile to build the ecca-proxy binary.

# Just so I won't forget it

.PHONY:	ecca-proxy release all rice-box dev clean distclean

all: ecca-proxy

release: rice-box ecca-proxy
dev: clean ecca-proxy


ecca-proxy:
	go build -o ecca-proxy *.go


rice-box: *.go
	go get github.com/GeertJohan/go.rice
	go get github.com/GeertJohan/go.rice/rice
	${GOPATH}/bin/rice embed-go -v

clean:
	rm -f rice-box.go
	rm -f ecca-proxy

distclean: clean
	rm -f ecca-proxy.sqlite3

run: ecca-proxy
	./ecca-proxy -v
