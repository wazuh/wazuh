# D5's FIM half: removal-driven row purge for the container staging buffer and
# reconcile plan (#40329).
#
# Standalone, like tests/unlink/, tests/txn/ and tests/alert/, and the cheapest
# of them: container_event_staging.hpp is header-only, so this needs nothing
# built and links nothing but the C++ runtime. Pid liveness is injected, so it
# spawns no processes either.
#
#   make check   -> builds and runs it
#   make clean

CXX      ?= c++
CXXFLAGS ?= -std=c++17 -O1 -Wall -Wextra -Wshadow -pthread

INCLUDES := -I../../include

container_removal_test: container_removal_test.cpp ../../include/container_event_staging.hpp ../../include/container_reconcile_plan.hpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ container_removal_test.cpp

check: container_removal_test
	./container_removal_test

clean:
	rm -f container_removal_test

.PHONY: check clean
