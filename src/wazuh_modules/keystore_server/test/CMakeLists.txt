cmake_minimum_required(VERSION 3.12.4)

project(keystore_server_tests)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include)
link_directories(${SRC_FOLDER}/external/googletest/lib)

file(GLOB UNIT_SRC_FILES ${CMAKE_CURRENT_LIST_DIR}/unit/*.cpp)

add_executable(keystore_server_utest ${UNIT_SRC_FILES})

target_link_libraries(
  keystore_server_utest
  debug gtestd
  debug gtest_maind
  optimized gtest
  optimized gtest_main
  keystore_server
  pthread
  wazuhext)

target_include_directories(
  keystore_server_utest
  PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../include
          ${SRC_FOLDER}/shared_modules/utils # socketWrapper.hpp for the test client
          ${SRC_FOLDER}/shared_modules/common
          ${SRC_FOLDER}/external/cJSON
          ${SRC_FOLDER}/external/nlohmann)

add_test(NAME keystore_server_utest COMMAND keystore_server_utest)
set_tests_properties(keystore_server_utest PROPERTIES LABELS keystore_server_utest)
