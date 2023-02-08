export GO111MODULE=on

.PHONY: all

all: build

build:
	go build ssllabs-scan-v3.go
