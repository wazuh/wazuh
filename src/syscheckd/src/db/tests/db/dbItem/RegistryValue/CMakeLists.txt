cmake_minimum_required(VERSION 3.12.4)

project(registryvalue_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

file(GLOB registryvalue_UNIT_TEST_SRC
    "*.cpp")

include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/rsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/src/)

file(GLOB REGISTRYVALUE_SRC "${SRC_FOLDER}/syscheckd/src/db/src/dbRegistryValue.cpp")

file(GLOB RSYNC_IMP_SRC
    "${SRC_FOLDER}/shared_modules/rsync/src/*.cpp")

file(GLOB DBSYNC_IMP_SRC
    "${SRC_FOLDER}/shared_modules/dbsync/src/*.cpp"
    "${SRC_FOLDER}/shared_modules/dbsync/src/sqlite/*.cpp")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    file(GLOB WINDOWS_REGISTRYVALUE_SRC "${SRC_FOLDER}/syscheckd/src/db/src/fimDBSpecializationWindows.cpp")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_executable(registryvalue_unit_test
    ${registryvalue_UNIT_TEST_SRC}
    ${REGISTRYVALUE_SRC}
    ${WINDOWS_REGISTRYVALUE_SRC}
    ${RSYNC_IMP_SRC}
    ${DBSYNC_IMP_SRC})

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
        crypto
        ws2_32
        crypt32
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
        crypto
        dl
    )
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME registryvalue_unit_test
         COMMAND registryvalue_unit_test)
