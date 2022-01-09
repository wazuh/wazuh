cmake_minimum_required(VERSION 3.12.4)

project(fim_db_wrapper_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

include_directories(${SRC_FOLDER}/syscheckd/src/db/tests/db/FIMDB)

file(GLOB fimDBHelper_UNIT_TEST_SRC
    "*.cpp")
file(GLOB FIMDB_IMP_SRC
    "${SRC_FOLDER}/syscheckd/src/db/src/fimDB.cpp")

add_executable(fim_db_wrapper_unit_test
    ${SRC_FOLDER}/syscheckd/src/db/tests/db/FIMDB/fimDBUtilsTest.h
    ${fimDBHelper_UNIT_TEST_SRC}
    ${FIMDB_IMP_SRC})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(fim_db_wrapper_unit_test
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
    target_link_libraries(fim_db_wrapper_unit_test
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

add_test(NAME fim_db_wrapper_unit_test
         COMMAND fim_db_wrapper_unit_test)
