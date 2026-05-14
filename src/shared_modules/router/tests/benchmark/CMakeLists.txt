cmake_minimum_required(VERSION 3.12.4)

project(router_benchmark_tests)

include_directories(${CMAKE_SOURCE_DIR}/external/benchmark/include/)

file(GLOB SOURCES
        *.cpp
        )

add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME}
        benchmark router
        )

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
