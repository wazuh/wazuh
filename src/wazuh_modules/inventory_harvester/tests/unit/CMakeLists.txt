cmake_minimum_required(VERSION 3.12.4)

project(harvester_utests)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage -fsanitize=address,leak,undefined")

file(GLOB UNIT_SRC_FILES
    ${UNIT_SRC_DIR}/*_test.cpp
    ${UNIT_SRC_DIR}/logger.cpp
)

add_executable(${PROJECT_NAME}
    ${UNIT_SRC_FILES}
)

target_link_libraries(${PROJECT_NAME}
    debug gtestd
    debug gmockd
    debug gtest_maind
    debug gmock_maind
    optimized gtest
    optimized gmock
    optimized gtest_main
    optimized gmock_main
)

target_include_directories(${PROJECT_NAME} PRIVATE ${TEST_SRC_DIR} ${TEST_MOCK_DIR})

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
