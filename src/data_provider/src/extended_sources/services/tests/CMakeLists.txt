cmake_minimum_required(VERSION 3.10)

project(extended_sources_services_unit_test)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_SOURCE_DIR}/../external/googletest/googletest/include/)
include_directories(${CMAKE_SOURCE_DIR}/../external/googletest/googlemock/include/)
link_directories(${CMAKE_SOURCE_DIR}/../external/googletest/lib/)

set(TEST_SRC "main.cpp")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    list(APPEND TEST_SRC test_services_windows.cpp)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND TEST_SRC test_systemd_units_linux.cpp)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    list(APPEND TEST_SRC test_launchd_darwin.cpp)
endif()

add_executable(extended_sources_services_unit_test ${TEST_SRC})

target_link_libraries(extended_sources_services_unit_test
    services
    gtestd
    gmockd
    gtest_maind
    gmock_maind
)

add_test(NAME ServicesTests COMMAND extended_sources_services_unit_test)
