cmake_minimum_required(VERSION 3.10)

project(extended_sources_browser_extensions_unit_test)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_SOURCE_DIR}/../external/googletest/googletest/include/)
include_directories(${CMAKE_SOURCE_DIR}/../external/googletest/googlemock/include/)
link_directories(${CMAKE_SOURCE_DIR}/../external/googletest/lib/)

set(TEST_SRC "main.cpp")

list(APPEND TEST_SRC test_safari_darwin.cpp)

add_executable(extended_sources_browser_extensions_unit_test ${TEST_SRC})
target_link_libraries(extended_sources_browser_extensions_unit_test
  browser_extensions
  gtestd
  gmockd
  gtest_maind
  gmock_maind
  pthread
)

add_test(NAME BrowsersExtensionsTests COMMAND extended_sources_browser_extensions_unit_test)