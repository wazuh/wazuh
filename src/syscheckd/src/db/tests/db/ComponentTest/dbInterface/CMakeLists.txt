cmake_minimum_required(VERSION 3.12.4)

project(fim_db_interface_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

file(GLOB DB_INTERFACE_TEST_SRC
    "*.cpp")

include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/rsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/src/)
include_directories(${SRC_FOLDER}/syscheckd/src/db/tests/db/FIMDB)


file(GLOB FILE_SRC
    "${SRC_FOLDER}/syscheckd/src/db/src/file.cpp"
    "${SRC_FOLDER}/syscheckd/src/db/src/db.cpp"
    "${SRC_FOLDER}/syscheckd/src/db/src/dbFileItem.cpp")

file(GLOB RSYNC_IMP_SRC
    "${SRC_FOLDER}/shared_modules/rsync/src/*.cpp")

file(GLOB DBSYNC_IMP_SRC
    "${SRC_FOLDER}/shared_modules/dbsync/src/*.cpp"
    "${SRC_FOLDER}/shared_modules/dbsync/src/sqlite/*.cpp")

file(GLOB REGISTRY_SRC
    "${SRC_FOLDER}/syscheckd/src/db/src/dbRegistry*.cpp")

file(GLOB FIMDB_SRC
     "${SRC_FOLDER}/syscheckd/src/db/src/fimDB.cpp")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    file(GLOB WINDOWS_DB_SRC "${SRC_FOLDER}/syscheckd/src/db/src/fimDBSpecializationWindows.cpp")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_executable(fim_db_interface_test
    ${DB_INTERFACE_TEST_SRC}
    ${REGISTRY_SRC}
    ${FILE_SRC}
    ${FIMDB_SRC}
    ${RSYNC_IMP_SRC}
    ${DBSYNC_IMP_SRC}
    ${WINDOWS_DB_SRC})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(fim_db_interface_test
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
        ssl
        crypt32
        -static-libgcc -static-libstdc++
    )
else()
    target_link_libraries(fim_db_interface_test
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
        crypto
        cjson
        dl
    )
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME fim_db_interface_test
         COMMAND fim_db_interface_test)
