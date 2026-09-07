# D16 settle test for the container staging buffer (#37532 WP1).
#
# Standalone, like tests/txn/ and tests/alert/, and the cheapest of the three:
# container_event_staging.hpp is header-only, so this needs nothing built and
# links nothing but the C++ runtime. Pid liveness is injected, so it spawns no
# processes either.
#
#   make check   -> builds and runs it
#   make clean

CXX      ?= c++
CXXFLAGS ?= -std=c++17 -O1 -Wall -Wextra -Wshadow -pthread

INCLUDES := -I../../include

container_settle_test: container_settle_test.cpp ../../include/container_event_staging.hpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ container_settle_test.cpp

check: container_settle_test
	./container_settle_test

clean:
	rm -f container_settle_test

.PHONY: check clean
