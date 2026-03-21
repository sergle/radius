FUZZTIME ?= 10s

.PHONY: build test bench fuzz clean

build:
	go build ./...
	go build -o examples/client/client       ./examples/client/
	go build -o examples/chap_client/chap_client ./examples/chap_client/
	go build -o examples/server/server       ./examples/server/

test:
	go test -v ./...

bench:
	go test -v -bench=. -run=^$$ ./...

fuzz:
	go test -fuzz=^FuzzDecodeRequest$$ -fuzztime=$(FUZZTIME) .
	go test -fuzz=^FuzzDecodeReply$$ -fuzztime=$(FUZZTIME) .
	go test -fuzz=^FuzzDecodeRequestPooled$$ -fuzztime=$(FUZZTIME) .
	go test -fuzz=^FuzzDecodeRequestLazy$$ -fuzztime=$(FUZZTIME) .

clean:
	go clean
