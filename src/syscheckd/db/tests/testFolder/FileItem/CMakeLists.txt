cmake_minimum_required(VERSION 3.12.4)

project(fileitem_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

file(GLOB fileitem_UNIT_TEST_SRC
    "*.cpp")

file(GLOB FILEITEM_SRC "${SRC_FOLDER}/syscheckd/db/src/dbFileItem.cpp")

add_executable(fileitem_unit_test
    ${fileitem_UNIT_TEST_SRC}
    ${FILEITEM_SRC})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(fileitem_unit_test
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
    target_link_libraries(fileitem_unit_test
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

add_test(NAME fileitem_unit_test
         COMMAND fileitem_unit_test)
