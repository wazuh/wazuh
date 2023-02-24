cmake_minimum_required(VERSION 3.12.4)

project(fim_registry_interface_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

file(GLOB REGISTRY_UNIT_TEST_SRC
         "*.cpp")

include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/rsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/src/)
include_directories(${SRC_FOLDER}/syscheckd/src/db/tests/db/FIMDB)
include_directories(${SRC_FOLDER}/syscheckd/src/db/tests/db/ComponentTest/dbInterface)

file(GLOB REGISTRY_SRC
         "${SRC_FOLDER}/syscheckd/src/db/src/registry.cpp"
         "${SRC_FOLDER}/syscheckd/src/db/src/db.cpp"
         "${SRC_FOLDER}/syscheckd/src/db/src/dbFileItem.cpp"
         "${SRC_FOLDER}/syscheckd/src/db/src/dbRegistry*.cpp")

file(GLOB FIMDB_SRC
         "${SRC_FOLDER}/syscheckd/src/db/src/fimDB.cpp")

file(GLOB RSYNC_IMP_SRC
         "${SRC_FOLDER}/shared_modules/rsync/src/*.cpp")

file(GLOB DBSYNC_IMP_SRC
         "${SRC_FOLDER}/shared_modules/dbsync/src/*.cpp"
         "${SRC_FOLDER}/shared_modules/dbsync/src/sqlite/*.cpp")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    file(GLOB WINDOWS_REGISTRY_SRC "${SRC_FOLDER}/syscheckd/src/db/src/fimDBSpecializationWindows.cpp")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_executable(fim_registry_interface_test
    ${REGISTRY_UNIT_TEST_SRC}
    ${REGISTRY_SRC}
    ${FIMDB_SRC}
    ${RSYNC_IMP_SRC}
    ${DBSYNC_IMP_SRC}
    ${WINDOWS_REGISTRY_SRC})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(fim_registry_interface_test
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
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME fim_registry_interface_test
         COMMAND fim_registry_interface_test)
