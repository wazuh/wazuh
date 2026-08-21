cmake_minimum_required(VERSION 3.12.4)

project(uds_http_server_tests)

# The C++17 FLOOR the library promises is enforced by CI through this target: every test TU --
# which includes every public and private header -- compiles at 17, so a C++20-ism entering the
# library fails the build instead of waiting for a strict-C++17 consumer (remoted_module) to
# find it. (The archive's own TUs are pinned to 17 in the library's CMakeLists for the same
# reason.)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)

link_directories(${SRC_FOLDER}/external/googletest/lib/)

file(GLOB UNIT_SRC_FILES ${CMAKE_CURRENT_LIST_DIR}/unit/*.cpp)

add_executable(uds_http_server_utest ${UNIT_SRC_FILES})

# No gtest_main: testMain.cpp owns main() because the binary must define and install its own
# Log::GLOBAL_LOG_FUNCTION before any test constructs a server (see testLogRecorder.hpp).
target_link_libraries(
  uds_http_server_utest
  debug gtestd
  debug gmockd
  optimized gtest
  optimized gmock
  wazuh_uds_http_server
  pthread)

target_include_directories(
  uds_http_server_utest
  PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../src # white-box targets: inFlightBudget.hpp, requestParser.hpp
          ${SRC_FOLDER}/shared_modules/utils # loggerHelper.h
          # The server tests drive a raw UDS client with standalone Asio directly. The library
          # links asio/llhttp PRIVATE, so neither propagates to this target.
          ${SRC_FOLDER}/external/asio/include
          ${SRC_FOLDER}/external/llhttp/include)

target_compile_definitions(uds_http_server_utest PRIVATE ASIO_STANDALONE)

# Plain add_test, NOT gtest_discover_tests: this suite has process-wide state by design (the
# single log sink, the static LogThrottle windows), and one process per case would change the
# behaviour under test.
add_test(NAME uds_http_server_utest COMMAND uds_http_server_utest)
set_tests_properties(uds_http_server_utest PROPERTIES LABELS uds_http_server_utest)
