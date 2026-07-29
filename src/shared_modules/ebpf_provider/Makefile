# eBPF Module (#37396) validation build. Standalone Makefile (not yet wired
# into the CMake project) so the engine can be iterated on and validated on
# a real kernel independent of the full Wazuh build — mirrors
# spike-37396/poc/Makefile's proven build recipe on this VM.
#
#   make        -> builds the BPF object + engine + test harness
#   make run    -> requires root (BPF load/attach)
#   make clean

CC      ?= cc
CLANG   ?= clang
BPFTOOL ?= bpftool
ARCH    := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')

INCLUDES := -Iinclude -Ibpf

all: rt_engine_harness

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

rt_file.bpf.o: bpf/rt_file.bpf.c vmlinux.h include/rt_event_contract.h
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -Ibpf -c bpf/rt_file.bpf.c -o $@

rt_engine.o: src/rt_engine.c include/rt_engine.h include/rt_event_contract.h
	$(CC) -O2 -Wall -Wextra $(INCLUDES) -c src/rt_engine.c -o $@

rt_engine_harness: rt_engine.o rt_file.bpf.o test/rt_engine_harness.c
	$(CC) -O2 -Wall -Wextra $(INCLUDES) -o $@ test/rt_engine_harness.c rt_engine.o -lbpf -lelf -lz

clean:
	rm -f rt_engine_harness rt_engine.o rt_file.bpf.o bpf/vmlinux.h

.PHONY: all clean
