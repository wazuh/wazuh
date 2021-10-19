cmake_minimum_required(VERSION 3.12.4)

project(registryvalue_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

file(GLOB registryvalue_UNIT_TEST_SRC
    "*.cpp")

file(GLOB REGISTRYVALUE_SRC "${SRC_FOLDER}/syscheckd/db/src/dbRegistryValue.cpp")

add_executable(registryvalue_unit_test
    ${registryvalue_UNIT_TEST_SRC}
    ${REGISTRYVALUE_SRC})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(registryvalue_unit_test
        debug gtestd
        debug gmockd
        debug gtest_maind
        debug gmock_maind
        optimized gtest
        optimized gmock
        optimized gtest_main
        optimized gmock_main
        pthread
        sqlite3
        cjson
        -static-libgcc -static-libstdc++
    )
else()
    target_link_libraries(registryvalue_unit_test
        debug gtestd
        debug gmockd
        debug gtest_maind
        debug gmock_maind
        optimized gtest
        optimized gmock
        optimized gtest_main
        optimized gmock_main
        pthread
        sqlite3
        cjson
        dl
    )
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME registryvalue_unit_test
         COMMAND registryvalue_unit_test)
