cmake_minimum_required(VERSION 3.12.4)

project(manager_certs_utest)

file(GLOB SOURCES *.cpp)

add_executable(${PROJECT_NAME} ${SOURCES})

# ../testPki.hpp, a sibling of unit/ (not vendored per-suite: one copy, shared by every case file here).
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)

# manager_certs_core links ca_bundle PUBLIC, which itself links `crypto` PUBLIC (ca_bundle/test/CMakeLists.txt),
# so this target gets manager_certs/ and ca_bundle/ headers plus the vendored OpenSSL archive testPki.hpp needs,
# all transitively -- no separate crypto link here.
target_link_libraries(
  ${PROJECT_NAME}
  debug gtestd
  debug gtest_maind
  optimized gtest
  optimized gtest_main
  manager_certs_core
  pthread)

# Every test registered here carries the module-wide `manager_certs` label: CI selects tests by ctest
# label (.github/actions/test_cpp runs `ctest -L <label>`), so `-L manager_certs` is what runs the whole
# module. The GTest keeps its target-name label as well, which is the selector the ASAN job uses to run
# only this binary.
add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
set_tests_properties(${PROJECT_NAME} PROPERTIES LABELS "${PROJECT_NAME};manager_certs")

# End-to-end: the CLI (bin/wazuh-manager-certs) for --version/--help with no configuration present
# (RF-10: the tool has to work with every daemon stopped and no manager home set).
add_test(NAME manager_certs_cli
         COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/../cli/manager_certs_cli_test.sh
                 $<TARGET_FILE:wazuh-manager-certs>)
set_tests_properties(manager_certs_cli PROPERTIES LABELS manager_certs)
