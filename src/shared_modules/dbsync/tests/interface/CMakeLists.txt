cmake_minimum_required(VERSION 3.12.4)

project(dbsync_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

include_directories(${CMAKE_SOURCE_DIR}/include/)
link_directories(${CMAKE_BINARY_DIR}/lib)


file(GLOB INTERFACE_UNITTEST_SRC
    "*.cpp"
    "${CMAKE_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_SOURCE_DIR}/src/sqlite/*.cpp")

add_executable(dbsync_unit_test 
    ${INTERFACE_UNITTEST_SRC} )
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(dbsync_unit_test
        debug gtestd
        debug gmockd
        debug gtest_maind
        debug gmock_maind
        optimized gtest
        optimized gmock
        optimized gtest_main
        optimized gmock_main
        sqlite3
        cjson
        pthread
        -static-libgcc -static-libstdc++
    )
else()
    target_link_libraries(dbsync_unit_test
        debug gtestd
        debug gmockd
        debug gtest_maind
        debug gmock_maind
        optimized gtest
        optimized gmock
        optimized gtest_main
        optimized gmock_main
        sqlite3
        cjson
        pthread
        dl
    )
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME dbsync_unit_test
         COMMAND dbsync_unit_test)
