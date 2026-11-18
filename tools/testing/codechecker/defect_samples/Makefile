# Makefile for CodeChecker defect validation samples.
# Called by run_comparison.sh when this directory exists in the source tree.
#
# Static-analysis targets (OBJS): captured by CodeChecker log and analyzed by
#   clangsa / cppcheck / clang-tidy.  defects_ctu_* exercise ENABLE_CTU=1
#   (inter-procedural null deref visible only across TU boundaries).
#   defects_infer exercises RUN_INFER=1 (fd leak + lock imbalance).
#
# Runtime target (TSAN_BIN): compiled with -fsanitize=thread and executed by
#   run_tsan_tests.sh when RUN_TSAN=1.  Excluded from static-analysis OBJS.

CC       ?= clang
CXX      ?= clang++
CFLAGS   += -g -O0 -Wall -pthread
CXXFLAGS += -g -O0 -Wall -std=c++17 -pthread

# Static-analysis object files (merged into compile_commands.json)
OBJS = defects_c.o defects_cpp.o \
       defects_ctu_callee.o defects_ctu_caller.o \
       defects_infer.o

# TSan standalone binary (built separately; run by run_tsan_tests.sh)
TSAN_BIN = defects_tsan

all: $(OBJS) $(TSAN_BIN)

defects_c.o: defects_c.c
	$(CC) $(CFLAGS) -c $< -o $@

defects_cpp.o: defects_cpp.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

defects_ctu_callee.o: defects_ctu_callee.c
	$(CC) $(CFLAGS) -c $< -o $@

defects_ctu_caller.o: defects_ctu_caller.c
	$(CC) $(CFLAGS) -c $< -o $@

defects_infer.o: defects_infer.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TSAN_BIN): defects_tsan.c
	$(CC) -g -O0 -Wall -fsanitize=thread -pthread $< -o $@

clean:
	rm -f $(OBJS) $(TSAN_BIN)

.PHONY: all clean
