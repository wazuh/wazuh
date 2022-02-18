# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# dependencies
CPMAddPackage(
  NAME RE2
  GITHUB_REPOSITORY google/re2
  GIT_TAG 2022-02-01
  VERSION release 2022-02-01
)

# Configuration regex test
add_executable(regex_bench
  ${BENCHMARK_SOURCE_DIR}/regex/regex_bench.cpp
)

# Build benchmarks
target_link_libraries(regex_bench benchmark::benchmark_main re2)
