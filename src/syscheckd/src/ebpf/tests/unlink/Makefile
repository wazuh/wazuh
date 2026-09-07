# D17 unlink-routing test for the container staging buffer and reconcile plan
# (#37532 WP3).
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

container_unlink_test: container_unlink_test.cpp ../../include/container_event_staging.hpp ../../include/container_reconcile_plan.hpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ container_unlink_test.cpp

check: container_unlink_test
	./container_unlink_test

clean:
	rm -f container_unlink_test

.PHONY: check clean
