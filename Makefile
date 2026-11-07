FUZZTIME ?= 10s

.PHONY: build test bench fuzz fix clean

build:
	go build ./...
	go build -o examples/client/client       ./examples/client/
	go build -o examples/chap_client/chap_client ./examples/chap_client/
	go build -o examples/server/server       ./examples/server/
	go build -o examples/eap/eap             ./examples/eap/
	go build -o examples/dictload/dictload   ./examples/dictload/

test:
	go test -v -p 1 ./...

bench:
	go test -v -p 1 -bench=. -run=^$$ ./...

fuzz:
	go test -fuzz=^FuzzDecodeRequest$$ -fuzztime=$(FUZZTIME) .
	go test -fuzz=^FuzzDecodeReply$$ -fuzztime=$(FUZZTIME) .
	go test -fuzz=^FuzzDecodeRequestPooled$$ -fuzztime=$(FUZZTIME) .
	go test -fuzz=^FuzzDecodeRequestLazy$$ -fuzztime=$(FUZZTIME) .
	go test -fuzz=^FuzzEapDecode$$ -fuzztime=$(FUZZTIME) .
	go test -fuzz=^FuzzTLVDecode$$ -fuzztime=$(FUZZTIME) .
	go test -fuzz=^FuzzTLVEncryptedDecode$$ -fuzztime=$(FUZZTIME) .
	go test -fuzz=^FuzzVSAFormatDecode$$ -fuzztime=$(FUZZTIME) .
	go test -fuzz=^FuzzExtendedDecode$$ -fuzztime=$(FUZZTIME) .

fix:
	go fix ./...

clean:
	go clean
