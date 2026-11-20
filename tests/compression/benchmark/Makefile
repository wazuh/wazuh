# Invoke from src with -f Makefile -f ../tests/compression/benchmark/Makefile.
compression-benchmark: $(filter-out monitord/main.o,$(monitor_o)) os_maild/sendcustomemail.o $(ZSTD_LIB) $(BUILD_LIBS) ../tests/compression/benchmark/driver.c
	$(OSSEC_CC) $(OSSEC_CFLAGS) -c ../tests/compression/benchmark/driver.c -o compression-benchmark.o
	$(OSSEC_CCBIN) $(OSSEC_LDFLAGS) compression-benchmark.o $(filter-out ../tests/compression/benchmark/driver.c,$^) $(OSSEC_LIBS) -o $@

.PHONY: benchmark-driver-check
benchmark-driver-check:
	$(OSSEC_CC) $(OSSEC_CFLAGS) -Werror -fsyntax-only ../tests/compression/benchmark/driver.c
