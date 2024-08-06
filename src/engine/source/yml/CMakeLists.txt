# ###################################################################################################
# Sources - Includes
# ###################################################################################################
add_library(yml STATIC
    ${CMAKE_CURRENT_LIST_DIR}/src/yml.cpp
)

target_link_libraries(yml yaml-cpp::yaml-cpp base)

target_include_directories(yml PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
)

if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

add_executable(yml_utest
    ${UNIT_SRC_DIR}/yml_test.cpp
)
target_link_libraries(yml_utest PRIVATE GTest::gtest_main base yml)
gtest_discover_tests(yml_utest)

set(TEST_FILE "${UNIT_SRC_DIR}/testFile.yml")
target_compile_definitions(yml_utest PRIVATE
  TEST_FILE="${TEST_FILE}"
)

endif(ENGINE_BUILD_TEST)
