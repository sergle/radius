.PHONY: build test bench clean

build:
	go build ./...

test:
	go test -v ./...

bench:
	go test -v -bench=. -run=^$$ ./...

clean:
	go clean
