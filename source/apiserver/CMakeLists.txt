set(API_SERVER_SOURCE_DIR ${ENGINE_SOURCE_DIR}/apiserver/src)
set(API_SERVER_INCLUDE_DIR ${ENGINE_SOURCE_DIR}/apiserver/include)

####################################################################################################
# Sources - Includes
####################################################################################################
add_library(apiserver STATIC
    ${API_SERVER_SOURCE_DIR}/apiServer.cpp
)

target_link_libraries(apiserver base httplib::httplib)

target_include_directories(apiserver
    PUBLIC
    ${API_SERVER_INCLUDE_DIR}
)

# Tests
if(!ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

add_executable(apiserver_utest
    ${UNIT_SRC_DIR}/apiServer_test.cpp
)

target_include_directories(apiserver_utest
    PRIVATE
    ${uvw_SOURCE_DIR}/src/
)

target_link_libraries(apiserver_utest PRIVATE GTest::gtest_main server libuv::uv_a)
gtest_discover_tests(apiserver_utest)

endif()
