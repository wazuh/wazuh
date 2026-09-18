cmake_minimum_required(VERSION 3.12.4)

project(ca_bundle_utest)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)

link_directories(${SRC_FOLDER}/external/googletest/lib/)

file(GLOB SOURCES *.cpp)

add_executable(${PROJECT_NAME} ${SOURCES})

# ca_bundle links `crypto` PUBLIC, so this target gets both the vendored OpenSSL archive (which
# testPki.hpp needs directly, to build its throwaway PKI in memory) and its include directories.
target_link_libraries(
  ${PROJECT_NAME}
  debug gtestd
  debug gtest_maind
  optimized gtest
  optimized gtest_main
  ca_bundle
  pthread)

# Every test registered here carries the module-wide `ca_bundle` label: CI selects tests by ctest
# label (.github/actions/test_cpp runs `ctest -L <label>`), so `-L ca_bundle` is what runs the whole
# module. The GTest keeps its target-name label as well, which is the selector the ASAN job uses to
# run only this binary.
add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
set_tests_properties(${PROJECT_NAME} PROPERTIES LABELS "${PROJECT_NAME};ca_bundle")
