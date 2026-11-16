# Invoke from src: make TARGET=server -f Makefile -f ../tests/compression/Makefile compression-test-driver
compression-test-driver: $(filter-out monitord/main.o,$(monitor_o)) os_maild/sendcustomemail.o $(ZSTD_LIB) $(BUILD_LIBS) ../tests/compression/driver.c
	$(OSSEC_CC) $(OSSEC_CFLAGS) -c ../tests/compression/driver.c -o compression-test-driver.o
	$(OSSEC_CCBIN) $(OSSEC_LDFLAGS) compression-test-driver.o $(filter-out ../tests/compression/driver.c,$^) $(OSSEC_LIBS) -o $@
