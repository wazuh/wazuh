cmake_minimum_required(VERSION 3.12.4)

project(vdscanner)

enable_testing()

file(GLOB VDSCANNER_SRC
    "src/*.cpp"
    "src/versionMatcher/*.cpp"
    )

# Add fpic flag
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(vdscanner STATIC
    ${VDSCANNER_SRC}
    )

target_include_directories(vdscanner PUBLIC include)

target_link_libraries(vdscanner PUBLIC database_feed)

add_subdirectory(tools)

# Tests
if(ENGINE_BUILD_TEST)
set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

#add_executable(vdscanner_ctest
#    ${COMPONENT_SRC_DIR}/store_test.cpp
#)
#target_link_libraries(vdscanner_ctest GTest::gtest_main)
#gtest_discover_tests(vdscanner_ctest)

add_executable(vdscanner_utest
    ${UNIT_SRC_DIR}/versionMatcher_test.cpp
    ${UNIT_SRC_DIR}/scannerHelper_test.cpp
    ${UNIT_SRC_DIR}/packageScanner_test.cpp
    ${UNIT_SRC_DIR}/factoryOrchestrator_test.cpp
    ${UNIT_SRC_DIR}/responseBuilder_test.cpp
    ${UNIT_SRC_DIR}/scanContext_test.cpp
    ${UNIT_SRC_DIR}/descriptionsHelper_test.cpp
)
target_compile_definitions(vdscanner_utest PUBLIC FLATBUFFER_SCHEMAS_DIR="${CMAKE_CURRENT_LIST_DIR}/../feedmanager/schemas/")
target_link_libraries(vdscanner_utest GTest::gmock GTest::gtest_main vdscanner feedmanager::mocks)
gtest_discover_tests(vdscanner_utest)
endif(ENGINE_BUILD_TEST)
