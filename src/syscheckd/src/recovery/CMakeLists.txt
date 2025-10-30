cmake_minimum_required(VERSION 3.12.4)

project(recovery)

enable_testing()

include_directories(${SRC_FOLDER}/shared_modules/utils)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/sync_protocol/include/)
include_directories(${SRC_FOLDER}/syscheckd)
include_directories(${SRC_FOLDER}/syscheckd/src/db/include/)
include_directories(${SRC_FOLDER}/syscheckd/src/db/src/)
include_directories(${CMAKE_SOURCE_DIR}/src/recovery/)

# Recovery source files are compiled as part of main syscheckd binary
# This CMakeLists.txt is mainly for organizing tests

if(UNIT_TEST)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    # Add any recovery-specific test flags if needed
  else()
    # Add any recovery-specific test flags if needed
  endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

  add_subdirectory(tests)
endif(UNIT_TEST)
