# SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
cmake_minimum_required(VERSION 3.12.4)

project(utils)

# Language level. The headers have no target of their own: each consumer compiles them under its own
# standard (C++20 across src/, C++17 in the engine and remoted_module), so they must stay C++17-clean.
# This file therefore sets no standard. The subdirectories that build something pin theirs:
# - tests/ pins C++17, the floor every consumer needs (README RNF-2);
# - flatbuffers/ pins C++17 for flatbuffer_tool, also configured standalone by CI;
# - benchmark/ takes the tree's default (C++20 from src/CMakeLists.txt).
if(NOT ${TARGET} STREQUAL "")
  if(${TARGET} STREQUAL "manager")
    add_subdirectory(flatbuffers)
  endif()
endif()

if(UNIT_TEST)
  enable_testing()
  if(NOT IS_AGENT)
    add_subdirectory(tests)

    if(NOT ((CMAKE_C_COMPILER MATCHES ".*ccc-analyzer")
            OR (CMAKE_CXX_COMPILER MATCHES ".*c\\+\\+-analyzer")))
      add_subdirectory(benchmark)
    endif()
  endif()
endif()
