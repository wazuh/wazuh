cmake_minimum_required(VERSION 3.12.4)

project(keystore_component_tests)

file(GLOB SOURCES
        *.cpp
        )

add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME}
        debug gtestd
        debug gtest_maind
        optimized gtest
        optimized gtest_main
        keystore
        pthread
        )

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
