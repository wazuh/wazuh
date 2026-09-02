# Makefile for the CodeChecker selftest scan path.
#
# run_comparison.sh executes `cd $WAZUH_DIR/src && make deps TARGET=...`
# followed by `CodeChecker log -b "make TARGET=... DEBUG=1"`.
# This Makefile satisfies those calls when WAZUH_DIR points to the selftest
# git repo (created at runtime in the container by run_ci.sh --selftest).
#
# During selftest setup, run_ci.sh copies the defect_samples .c/.cpp files
# alongside this Makefile so that CodeChecker log captures their compilation.

CC      ?= clang
CXX     ?= clang++
CFLAGS  += -g -O0 -Wall -pthread
CXXFLAGS+= -g -O0 -Wall -std=c++17 -pthread

SRCS    := $(wildcard *.c)
CXXSRCS := $(wildcard *.cpp)
OBJS    := $(SRCS:.c=.o) $(CXXSRCS:.cpp=.o)

# Default target — must come first so that `make TARGET=server` compiles
# everything. run_comparison.sh passes TARGET=server as a *variable*, not a
# make goal, so make always runs the default (first) target.
all agent server manager local: $(OBJS)

# deps is called explicitly by run_comparison.sh before the log step.
# It is intentionally a no-op — the selftest tree has no external deps.
deps:
	@echo "selftest: no external deps"

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS)

.PHONY: deps agent server manager local all clean
