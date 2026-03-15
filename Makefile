FUZZTIME ?= 10s

.PHONY: build test bench fuzz clean

build:
	go build ./...

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
