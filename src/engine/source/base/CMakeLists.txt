# FIXME: Base should be refactored to be an OBJECT library so other modules can simply include what they need.
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

add_library(base STATIC
    logging/logging.hpp
    utils/wazuhProtocol/wazuhResponse.hpp
    utils/wazuhProtocol/wazuhRequest.hpp
    utils/wazuhProtocol/wazuhRequest.cpp
    utils/baseMacros.hpp
    utils/baseMacros.cpp
    utils/ipUtils.cpp
    utils/ipUtils.hpp
    utils/stringUtils.cpp
    utils/stringUtils.hpp
    result.hpp
    baseTypes.hpp
    expression.cpp
    error.hpp
    parseEvent.cpp
    parseEvent.hpp
    name.hpp
    )

if(PROFILE_BUILD)
    target_link_libraries(base
        PUBLIC
        profile
        )
endif()

target_link_libraries(base
    PUBLIC
    dl
    fmt
    spdlog
    json
    )

target_include_directories(base
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
    ${spdlog_SOURCE_DIR}/include
    ${rapidjson_SOURCE_DIR}/include
    ${ENGINE_SOURCE_DIR}/json
    ${ENGINE_SOURCE_DIR}/base
    ${ENGINE_SOURCE_DIR} # TODO remove when BUILDER is updated (#include <builder/builder.hpp)
)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

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
)
target_include_directories(base_utest
    PRIVATE
    ${TEST_SRC_DIR}
    ${CMAKE_CURRENT_LIST_DIR}
)
target_link_libraries(base_utest
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
    ${CMAKE_CURRENT_LIST_DIR}
)
target_link_libraries(base_logger_utest
    PRIVATE
    base
    gtest_main
)
gtest_discover_tests(base_logger_utest)

endif(ENGINE_BUILD_TEST)
