cmake_minimum_required(VERSION 2.6.4)

project(syscollectorimp_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")


link_directories(${SRC_FOLDER}/shared_modules/dbsync/build/lib)
link_directories(${SRC_FOLDER}/shared_modules/rsync/build/lib)

file(GLOB SYSCOLLECTOR_IMP_UNIT_TEST_SRC
    "*.cpp")

file(GLOB SYSCOLLECTOR_IMP_SRC
    "${CMAKE_SOURCE_DIR}/syscollectorImp.cpp")

add_executable(syscollectorimp_unit_test 
    ${SYSCOLLECTOR_IMP_UNIT_TEST_SRC}
    ${SYSCOLLECTOR_IMP_SRC})
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(syscollectorimp_unit_test
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
        rsync
        dbsync
        -static-libgcc -static-libstdc++
    )
else()
    target_link_libraries(syscollectorimp_unit_test
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
        rsync
        dbsync
        dl
    )
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME syscollectorimp_unit_test
         COMMAND syscollectorimp_unit_test)