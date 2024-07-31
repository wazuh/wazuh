####################################################################################################
# logging
####################################################################################################
CPMAddPackage(
  NAME fmt
  GITHUB_REPOSITORY fmtlib/fmt
  GIT_TAG "8.1.1"
  OPTIONS "FMT_HEADER_ONLY ON"
)

CPMAddPackage(
  NAME spdlog
  GITHUB_REPOSITORY gabime/spdlog
  GIT_TAG "v1.11.0"
  OPTIONS "SPDLOG_FMT_EXTERNAL_HO ON"
)

add_dependencies(spdlog fmt)

####################################################################################################
# json
####################################################################################################
CPMAddPackage(
    NAME rapidjson
    GITHUB_REPOSITORY Tencent/rapidjson
    GIT_TAG 8261c1ddf43f10de00fd8c9a67811d1486b2c784 # Latest master commit from 21/03/2022
    OPTIONS
    "RAPIDJSON_BUILD_DOC OFF"
    "RAPIDJSON_BUILD_EXAMPLES OFF"
    "RAPIDJSON_BUILD_TESTS OFF"
    DOWNLOAD_ONLY YES
    )

####################################################################################################
# BASE
####################################################################################################
# Defs
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

add_library(base STATIC
    ${SRC_DIR}/utils/wazuhProtocol/wazuhRequest.cpp
    ${SRC_DIR}/utils/ipUtils.cpp
    ${SRC_DIR}/utils/stringUtils.cpp
    ${SRC_DIR}/expression.cpp
    ${SRC_DIR}/parseEvent.cpp
    ${SRC_DIR}/json.cpp
    ${SRC_DIR}/logging.cpp
)
target_include_directories(base
    PUBLIC
    ${INC_DIR}
    ${spdlog_SOURCE_DIR}/include
    ${rapidjson_SOURCE_DIR}/include

    PRIVATE
    ${INC_DIR}/base
    ${SRC_DIR}
)
target_link_libraries(base
    PUBLIC
    fmt

    PRIVATE
    spdlog
)

# Tests

if(ENGINE_BUILD_TEST)

set(TEST_DIR ${CMAKE_CURRENT_LIST_DIR}/test)
set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

add_library(base_test INTERFACE)
target_include_directories(base_test INTERFACE ${TEST_DIR}/include)
add_library(base::test ALIAS base_test)

add_executable(base_utest
    ${UNIT_SRC_DIR}/stringUtils_test.cpp
    ${UNIT_SRC_DIR}/ipUtils_test.cpp
    ${UNIT_SRC_DIR}/result_test.cpp
    ${UNIT_SRC_DIR}/graph_test.cpp
    ${UNIT_SRC_DIR}/name_test.cpp
    ${UNIT_SRC_DIR}/utils/wazuhProtocol/wazuhRequest_test.cpp
    ${UNIT_SRC_DIR}/utils/wazuhProtocol/wazuhResponse_test.cpp
    ${UNIT_SRC_DIR}/parseEvent_test.cpp
    ${UNIT_SRC_DIR}/dotPath_test.cpp
    ${UNIT_SRC_DIR}/json_test.cpp
    ${UNIT_SRC_DIR}/error_test.cpp
    ${UNIT_SRC_DIR}/timer_test.cpp
)
target_include_directories(base_utest
    PRIVATE
    ${TEST_SRC_DIR}
    ${SRC_DIR}
    ${INC_DIR}/base
)
target_link_libraries(base_utest
    PUBLIC
    base::test

    PRIVATE
    base
    gtest_main
)
gtest_discover_tests(base_utest)

# TODO this test needs to be instantiated alone because the logger is initialized on tests
add_executable(base_logger_utest
    ${UNIT_SRC_DIR}/logger_test.cpp
)
target_include_directories(base_logger_utest
    PRIVATE
    ${TEST_SRC_DIR}
    ${INC_DIR}/base
)
target_link_libraries(base_logger_utest
    PRIVATE
    base
    gtest_main
)
gtest_discover_tests(base_logger_utest)

endif(ENGINE_BUILD_TEST)
