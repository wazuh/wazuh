cmake_minimum_required(VERSION 3.12.4)

project(harvester_tests)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/../src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/mocks)
set(UNIT_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/unit)

link_directories(${SRC_FOLDER}/external/googletest/lib/)

add_subdirectory(unit)
# add_subdirectory(component)
# add_subdirectory(benchmark)
