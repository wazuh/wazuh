# ###################################################################################################
# Dependencies
# ###################################################################################################
# yaml-cpp::yaml-cpp vs yaml-cpp #FIXME 70 stars on github
CPMAddPackage(
    NAME yaml-cpp
    GITHUB_REPOSITORY jbeder/yaml-cpp
    GIT_TAG yaml-cpp-0.7.0
    VERSION 0.7.0
    OPTIONS
    "YAML_BUILD_SHARED_LIBS OFF"
    "YAML_CPP_BUILD_TESTS OFF"
    EXCLUDE_FROM_ALL YES
)

# ###################################################################################################
# Sources - Includes
# ###################################################################################################
add_library(yml STATIC
    ${CMAKE_CURRENT_LIST_DIR}/src/yml.cpp
)

target_link_libraries(yml yaml-cpp base)

target_include_directories(yml PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
)

if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

add_executable(yml_utest
    ${UNIT_SRC_DIR}/yml_test.cpp
)
target_link_libraries(yml_utest PRIVATE gtest_main base yml)
gtest_discover_tests(yml_utest)

set(TEST_FILE "${UNIT_SRC_DIR}/testFile.yml")
target_compile_definitions(yml_utest PRIVATE
  TEST_FILE="${TEST_FILE}"
)

endif(ENGINE_BUILD_TEST)
