# manager_benchmark sender — build and codegen.
#
# The FlatBuffers Go bindings are generated from the shared schema, never
# committed (see docu/05-flatbuffers-messages.md). `make generate` must run
# before `make build` on a clean checkout; `make all` does both.

SCHEMA := ../../../src/shared_modules/utils/flatbuffers/schemas/inventorySync.fbs
FLATC  ?= ../../../src/external/flatbuffers/build/flatc

.PHONY: all generate build vet test clean

all: generate build

generate:
	@mkdir -p internal/fb
	$(FLATC) --go -o internal/fb $(SCHEMA)

build:
	go build -o benchmark_sender ./cmd/benchmark_sender

vet:
	go vet ./...

test:
	go test ./...

clean:
	rm -rf internal/fb benchmark_sender
