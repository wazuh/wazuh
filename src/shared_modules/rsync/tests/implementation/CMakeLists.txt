cmake_minimum_required(VERSION 3.12.4)

project(rsync_implementation_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

include_directories(${CMAKE_SOURCE_DIR}/include/)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/src/)
link_directories(${CMAKE_BINARY_DIR}/lib)


file(GLOB INTERFACE_UNITTEST_SRC
    "*.cpp"
    "${CMAKE_SOURCE_DIR}/src/*.cpp")

file(GLOB DBSYNC_IMP_SRC
    "${SRC_FOLDER}/shared_modules/dbsync/src/*.cpp"
    "${SRC_FOLDER}/shared_modules/dbsync/src/sqlite/*.cpp")

add_executable(rsync_implementation_unit_test
    ${INTERFACE_UNITTEST_SRC}
    ${DBSYNC_IMP_SRC} )

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(rsync_implementation_unit_test
        debug gtestd
        debug gmockd
        debug gtest_maind
        debug gmock_maind
        optimized gtest
        optimized gmock
        optimized gtest_main
        optimized gmock_main
        crypto
        cjson
        sqlite3
        pthread
        ws2_32
        crypt32
        -static-libgcc -static-libstdc++
    )
else()
    target_link_libraries(rsync_implementation_unit_test
        debug gtestd
        debug gmockd
        debug gtest_maind
        debug gmock_maind
        optimized gtest
        optimized gmock
        optimized gtest_main
        optimized gmock_main
        crypto
        cjson
        sqlite3
        pthread
        dl
    )
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME rsync_implementation_unit_test
         COMMAND rsync_implementation_unit_test)