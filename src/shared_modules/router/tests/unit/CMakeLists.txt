cmake_minimum_required(VERSION 3.12.4)

project(router_unit_tests)

file(GLOB SOURCES
        *.cpp
        )

add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME}
        gtest
        gtest_main
        router
        )

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
