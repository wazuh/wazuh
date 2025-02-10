cmake_minimum_required(VERSION 3.12.4)

project(harvester_tests)

# include_directories(${CMAKE_SOURCE_DIR})
# include_directories(${CMAKE_SOURCE_DIR}/include/)
include_directories(mocks/)
# include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
# include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)
# include_directories(${SRC_FOLDER}/wazuh_modules/vulnerability_scanner/src/)
# include_directories(${SRC_FOLDER}/wazuh_modules/vulnerability_scanner/include/)
# include_directories(${SRC_FOLDER}/wazuh_modules/vulnerability_scanner/src/databaseFeedManager/)

# link_directories(${SRC_FOLDER}/external/googletest/lib/)

# add_subdirectory(unit)
# add_subdirectory(component)
# add_subdirectory(benchmark)
set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/../src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/mocks)
set(UNIT_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/unit)
set(COMPONENT_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/component)

message("[?] Source directory: " ${TEST_SRC_DIR})
message("[?] Mocks directory: " ${TEST_MOCK_DIR})
message("[?] Unit test directory: " ${UNIT_SRC_DIR})
message("[?] Component tests directory: " ${COMPONENT_SRC_DIR})

file(GLOB UNIT_SRC_FILES
    ${UNIT_SRC_DIR}/*_test.cpp
    ${UNIT_SRC_DIR}/logger.cpp
    )

message("[?] Files to compile: " ${UNIT_SRC_FILES})

add_executable(inventory_harvester_utest
    ${UNIT_SRC_FILES}
)

target_link_libraries(inventory_harvester_utest gtest gtest_main gmock)
target_include_directories(inventory_harvester_utest PRIVATE ${TEST_SRC_DIR} ${TEST_MOCK_DIR})
