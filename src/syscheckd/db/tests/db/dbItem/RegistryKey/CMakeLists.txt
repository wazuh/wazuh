cmake_minimum_required(VERSION 3.12.4)

project(registrykey_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

file(GLOB registrykey_UNIT_TEST_SRC
    "*.cpp")

file(GLOB REGISTRYKEY_SRC "${SRC_FOLDER}/syscheckd/db/src/dbRegistryKey.cpp")

add_executable(registrykey_unit_test
    ${registrykey_UNIT_TEST_SRC}
    ${REGISTRYKEY_SRC})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(registrykey_unit_test
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
    target_link_libraries(registrykey_unit_test
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

add_test(NAME registrykey_unit_test
         COMMAND registrykey_unit_test)
