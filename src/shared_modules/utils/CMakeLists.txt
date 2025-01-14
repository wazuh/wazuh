cmake_minimum_required(VERSION 3.12.4)

project(utils)

enable_testing()

if(UNIT_TEST)
    add_subdirectory(tests)

    if(NOT ((CMAKE_C_COMPILER MATCHES ".*ccc-analyzer") OR (CMAKE_CXX_COMPILER MATCHES ".*c\\+\\+-analyzer")))
      add_subdirectory(benchmark)
    endif()
endif()

if (NOT ${TARGET} STREQUAL "")
  if (${TARGET} STREQUAL "server")
      add_subdirectory(flatbuffers)
  endif()
endif()
