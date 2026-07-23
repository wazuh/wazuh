# spike #37396 throwaway PoC.
#
#  make sim     -> builds sim-only (NO libbpf/clang/kernel needed). Run: ./poc_sim --sim
#  make bpf     -> builds the real BPF object + libbpf dispatcher (needs clang,
#                  libbpf-dev, bpftool, /sys/kernel/btf/vmlinux, root to run).
#  make clean

CC      ?= cc
CLANG   ?= clang
BPFTOOL ?= bpftool
ARCH    := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')

# ---- sim-only build: proves fan-out logic anywhere ----
sim: poc_sim
poc_sim: dispatcher.c fanout.c fanout.h
	$(CC) -DPOC_SIM_ONLY -O2 -Wall -Wextra -pthread -o $@ dispatcher.c fanout.c

# ---- real BPF build ----
bpf: poc_bpf

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

file_open.bpf.o: file_open.bpf.c vmlinux.h
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
	    -I. -c file_open.bpf.c -o $@

poc_bpf: dispatcher.c fanout.c fanout.h file_open.bpf.o
	$(CC) -O2 -Wall -Wextra -pthread -o $@ dispatcher.c fanout.c -lbpf

# ---- exec probe: tracepoint/sched_process_exec (portable event class) ----
exec: exec_probe
exec_probe.bpf.o: exec_probe.bpf.c vmlinux.h
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I. -c exec_probe.bpf.c -o $@
exec_probe: exec_probe.c exec_probe.bpf.o
	$(CC) -O2 -Wall -o $@ exec_probe.c -lbpf

clean:
	rm -f poc_sim poc_bpf file_open.bpf.o exec_probe exec_probe.bpf.o vmlinux.h

.PHONY: sim bpf exec clean
