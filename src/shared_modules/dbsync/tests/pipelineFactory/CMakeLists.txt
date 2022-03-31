cmake_minimum_required(VERSION 3.12.4)

project(dbsyncPipelineFactory_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

include_directories(${CMAKE_SOURCE_DIR}/src/)
include_directories(${CMAKE_SOURCE_DIR}/utils/)
link_directories(${CMAKE_BINARY_DIR}/lib)


file(GLOB PIPELINE_FACTORY_UNITTEST_SRC
    "*.cpp")

include_directories(${CMAKE_SOURCE_DIR}/include/)
link_directories(${CMAKE_BINARY_DIR}/lib)

file(GLOB PIPELINE_FACTORY_SRC
    "${CMAKE_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_SOURCE_DIR}/src/sqlite/*.cpp")

add_executable(dbsyncPipelineFactory_unit_test 
    ${PIPELINE_FACTORY_UNITTEST_SRC}
    ${PIPELINE_FACTORY_SRC})
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(dbsyncPipelineFactory_unit_test
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
    target_link_libraries(dbsyncPipelineFactory_unit_test
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


add_test(NAME dbsyncPipelineFactory_unit_test
         COMMAND dbsyncPipelineFactory_unit_test)
