# Makefile to build the ecca-proxy binary.

# Just so I won't forget it

.PHONY:	ecca-proxy

ecca-proxy:
	go build -o ecca-proxy *.go