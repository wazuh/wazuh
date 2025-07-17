cmake_minimum_required(VERSION 3.12.4)

project(indexer_connector_utest)

file(GLOB SOURCES
        *.cpp

)

add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME}
        urlrequest
        debug gtestd
        debug gtest_maind
        debug gmockd
        debug gmock_maind
        optimized gtest
        optimized gtest_main
        optimized gmock
        optimized gmock_main
        keystore
        pthread
)

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
set_tests_properties(${PROJECT_NAME} PROPERTIES LABELS ${PROJECT_NAME})
