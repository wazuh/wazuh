# eBPF Module (#37396) validation build. Standalone Makefile (not yet wired
# into the CMake project) so the engine can be iterated on and validated on
# a real kernel independent of the full Wazuh build — mirrors
# spike-37396/poc/Makefile's proven build recipe on this VM.
#
#   make        -> builds the BPF object + engine + test harness
#   make run    -> requires root (BPF load/attach)
#   make check  -> builds and runs the contract tests (no kernel, no root)
#   make check-kernel -> teardown test; needs the BPF object and root
#   make clean
#
# On a host whose /usr/sbin/bpftool is the Debian kernel-version dispatch stub
# (it exits non-zero with "bpftool not found for kernel ..."), point BPFTOOL at
# a real one, e.g.
#   make BPFTOOL=/usr/lib/linux-hwe-7.0-tools-7.0.0-29/bpftool

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
	$(CC) -O2 -Wall -Wextra $(INCLUDES) -o $@ test/rt_engine_harness.c rt_engine.o -ldl

# Contract tests: no BPF object, no kernel, no root — so this target must not
# depend on rt_file.bpf.o (that is the point of keeping them separate from the
# harness, which does need a real kernel to be useful).
rt_engine_contract_test: rt_engine.o test/rt_engine_contract_test.c
	$(CC) -O2 -Wall -Wextra $(INCLUDES) -o $@ test/rt_engine_contract_test.c rt_engine.o -ldl

check: rt_engine_contract_test
	./rt_engine_contract_test

# Teardown test: needs a real kernel, the BPF object and root, so it is a
# separate target from `check` and exits 77 (skipped) when it cannot load.
rt_engine_leak_test: rt_engine.o test/rt_engine_leak_test.c
	$(CC) -O2 -Wall -Wextra $(INCLUDES) -o $@ test/rt_engine_leak_test.c rt_engine.o -ldl

rt_engine_drops_test: rt_engine.o test/rt_engine_drops_test.c
	$(CC) -O2 -Wall -Wextra $(INCLUDES) -o $@ test/rt_engine_drops_test.c rt_engine.o -ldl

rt_engine_filter_test: rt_engine.o test/rt_engine_filter_test.c
	$(CC) -O2 -Wall -Wextra $(INCLUDES) -o $@ test/rt_engine_filter_test.c rt_engine.o -ldl

check-kernel: rt_engine_leak_test rt_engine_drops_test rt_engine_filter_test rt_file.bpf.o
	sudo ./rt_engine_leak_test ./rt_file.bpf.o
	sudo ./rt_engine_drops_test ./rt_file.bpf.o
	sudo ./rt_engine_filter_test ./rt_file.bpf.o

clean:
	rm -f rt_engine_harness rt_engine_contract_test rt_engine_leak_test rt_engine_drops_test rt_engine_filter_test rt_engine.o rt_file.bpf.o bpf/vmlinux.h

.PHONY: all check clean
