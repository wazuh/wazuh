# Makefile for CodeChecker defect validation samples.
# Called by run_comparison.sh when this directory exists in the source tree
# (test/codechecker-defect-samples branch only).

CC       ?= clang
CXX      ?= clang++
CFLAGS   += -g -O0 -Wall -pthread
CXXFLAGS += -g -O0 -Wall -std=c++17

OBJS = defects_c.o defects_cpp.o

all: $(OBJS)

defects_c.o: defects_c.c
	$(CC) $(CFLAGS) -c $< -o $@

defects_cpp.o: defects_cpp.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS)

.PHONY: all clean
