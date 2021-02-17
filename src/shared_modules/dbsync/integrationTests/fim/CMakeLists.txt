cmake_minimum_required(VERSION 3.12.4)

project(fim_integration_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

include_directories(${CMAKE_SOURCE_DIR}/include/)
link_directories(${CMAKE_BINARY_DIR}/lib)

file(GLOB INTERFACE_UNITTEST_SRC
    "*.cpp")

file(GLOB DBSYNC_IMP_SRC
    "${SRC_FOLDER}/shared_modules/dbsync/src/*.cpp"
    "${SRC_FOLDER}/shared_modules/dbsync/src/sqlite/*.cpp")

add_executable(fim_integration_test 
    ${INTERFACE_UNITTEST_SRC} 
    ${DBSYNC_IMP_SRC})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(fim_integration_test
        debug gtestd
        debug gmockd
        debug gtest_maind
        debug gmock_maind
        optimized gtest
        optimized gmock
        optimized gtest_main
        optimized gmock_main
        cjson
        sqlite3
        pthread
        -static-libgcc -static-libstdc++
    )
else()
    target_link_libraries(fim_integration_test
        debug gtestd
        debug gmockd
        debug gtest_maind
        debug gmock_maind
        optimized gtest
        optimized gmock
        optimized gtest_main
        optimized gmock_main
        cjson
        sqlite3
        pthread
        dl
    )
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
add_test(NAME fim_integration_test
         COMMAND fim_integration_test)