cmake_minimum_required(VERSION 3.12.4)

project(fim_file_interface_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g -fsanitize=address --coverage")

file(GLOB FILE_UNIT_TEST_SRC
    "*.cpp")

include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/rsync/include/)
include_directories(${SRC_FOLDER}/syscheckd/db/tests/db/FIMDB)

link_directories(${SRC_FOLDER}/shared_modules/dbsync/build/lib)
link_directories(${SRC_FOLDER}/shared_modules/rsync/build/lib)

file(GLOB FILE_SRC
    "${SRC_FOLDER}/syscheckd/db/src/file.cpp"
    "${SRC_FOLDER}/syscheckd/db/src/dbFileItem.cpp")

file(GLOB FIMDB_SRC
     "${SRC_FOLDER}/syscheckd/db/src/fimDB.cpp")

add_executable(fim_file_interface_test
    ${FILE_UNIT_TEST_SRC}
    ${FILE_SRC}
    ${FIMDB_SRC})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(fim_file_interface_test
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
        dbsync
        rsync
        cjson
        -static-libgcc -static-libstdc++
    )
else()
    target_link_libraries(fim_file_interface_test
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
        dbsync
        rsync
        cjson
        dl
    )
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME fim_file_interface_test
         COMMAND fim_file_interface_test)
