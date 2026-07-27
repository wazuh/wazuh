# Makefile for the Go benchmark_sender. Invoked from the parent build via
# `make benchmark_sender_go`, or directly from this directory.
#
# Layout: tool_simulator/ lives under
#   wazuh/src/wazuh_modules/inventory_sync/benchmark/tool_simulator/
# i.e. five directory levels below the repo root (../../../../..).

WAZUH_REPO  ?= ../../../../..
FLATC       := $(WAZUH_REPO)/src/external/flatbuffers/build/flatc
SCHEMA_FBS  := $(WAZUH_REPO)/src/shared_modules/utils/flatbuffers/schemas/inventorySync.fbs

GO          ?= go
GOFLAGS     := -trimpath

FB_GO_DIR   := internal/fb/Wazuh/SyncSchema
FB_STUBS    := $(FB_GO_DIR)/Message.go

BIN         := benchmark_sender

.PHONY: all benchmark_sender_go test regen_fb_stubs clean_go

all: benchmark_sender_go

benchmark_sender_go: $(FB_STUBS)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o $(BIN) ./cmd/benchmark_sender

# Regenerate Go FlatBuffers stubs. Committed; only run on schema changes.
regen_fb_stubs:
	@if [ ! -x "$(FLATC)" ]; then \
		echo "flatc not found at $(FLATC); build it first"; exit 1; \
	fi
	rm -rf internal/fb
	mkdir -p internal/fb
	$(FLATC) --go -o internal/fb $(SCHEMA_FBS)

$(FB_STUBS):
	@if [ ! -f "$@" ]; then $(MAKE) regen_fb_stubs; fi

test:
	$(GO) test ./...

clean_go:
	rm -f $(BIN)
