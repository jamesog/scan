.PHONY: all
all: build

.PHONY: build
build: scan

dirs    := $(shell go list -f '{{.Dir}}' ./...)
gofiles := $(foreach dir,$(dirs),$(wildcard $(dir)/*.go))

scan: $(gofiles)
	go build

.PHONY: sample-data
sample-data:
	curl -s -H "Content-Type: application/json" \
		-d '[{"ip":"192.0.2.1","ports":[{"port":80,"proto":"tcp","status":"open","reason":"syn-ack","ttl":57}]}]' \
		localhost:8080/results
