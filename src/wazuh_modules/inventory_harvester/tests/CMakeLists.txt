cmake_minimum_required(VERSION 3.12.4)

project(harvester_tests)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/../src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/mocks)
set(UNIT_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/unit)

link_directories(${SRC_FOLDER}/external/googletest/lib/)

file(GLOB UNIT_SRC_FILES
    ${UNIT_SRC_DIR}/*_test.cpp
    ${UNIT_SRC_DIR}/logger.cpp
    )

message("[?] Files to compile: " ${UNIT_SRC_FILES})

add_executable(inventory_harvester_utest
    ${UNIT_SRC_FILES}
)

target_link_libraries(inventory_harvester_utest
    debug gtestd
    debug gmockd
    debug gtest_maind
    debug gmock_maind
    optimized gtest
    optimized gmock
    optimized gtest_main
    optimized gmock_main
)

target_include_directories(inventory_harvester_utest PRIVATE ${TEST_SRC_DIR} ${TEST_MOCK_DIR})
add_test(NAME inventory_harvester_utest COMMAND inventory_harvester_utest)
set_tests_properties(inventory_harvester_utest PROPERTIES LABELS "inventory_harvester_utest")


file(GLOB COMPONENT_SRC_FILES
    ${COMPONENT_SRC_DIR}/*_test.cpp
    ${COMPONENT_SRC_DIR}/logger.cpp
    )

message("[?] Files to compile: " ${COMPONENT_SRC_FILES})

add_executable(inventory_harvester_ctest
    ${COMPONENT_SRC_FILES}
)

target_link_libraries(inventory_harvester_ctest
    debug gtestd
    debug gmockd
    debug gtest_maind
    debug gmock_maind
    optimized gtest
    optimized gmock
    optimized gtest_main
    optimized gmock_main
)

target_include_directories(inventory_harvester_ctest PRIVATE ${TEST_SRC_DIR} ${TEST_MOCK_DIR})
add_test(NAME inventory_harvester_ctest COMMAND inventory_harvester_ctest)
set_tests_properties(inventory_harvester_ctest PROPERTIES LABELS "inventory_harvester_ctest")
