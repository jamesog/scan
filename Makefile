GOBINDATA = $(shell go env GOPATH)/bin/go-bindata

.PHONY: all
all: build

.PHONY: build
build: assets scan

dirs    := $(shell go list -f '{{.Dir}}' ./...)
gofiles := $(foreach dir,$(dirs),$(wildcard $(dir)/*.go))

scan: $(gofiles)
	go build

.PHONY: assets
assets: bindata.go

bindata.go: $(GOBINDATA) views/*.html
	go generate

$(GOBINDATA):
	go get github.com/go-bindata/go-bindata/...
