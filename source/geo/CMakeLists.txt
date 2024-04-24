# Defs
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

add_library(geo_igeo INTERFACE)
target_include_directories(geo_igeo INTERFACE ${IFACE_DIR})
target_link_libraries(geo_igeo INTERFACE json base)
add_library(geo::igeo ALIAS geo_igeo)

CPMAddPackage(
    NAME libmaxminddb
    GITHUB_REPOSITORY maxmind/libmaxminddb
    GIT_TAG 1.9.1
    OPTIONS
    "BUILD_SHARED_LIBS OFF"
    "BUILD_TESTING OFF"
)
set(SRCS
    ${SRC_DIR}/manager.cpp
    ${SRC_DIR}/downloader.cpp
    ${SRC_DIR}/locator.cpp
)
set(PRIVATE_LINKS
    maxminddb::maxminddb
    CURL::libcurl
)
set(PUBLIC_LINKS
    geo::igeo
    store::istore
)
add_library(geo
      ${SRCS}
)
target_include_directories(geo
    PUBLIC
    ${INC_DIR}

    PRIVATE
    ${SRC_DIR}
    ${INC_DIR}/geo
)
target_link_libraries(geo
    PUBLIC
    ${PUBLIC_LINKS}

    PRIVATE
    ${PRIVATE_LINKS}
)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)
set(MMDB_PATH_TEST ${TEST_SRC_DIR}/testdb.mmdb)

add_library(geo_mocks INTERFACE)
target_include_directories(geo_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(geo_mocks INTERFACE geo::igeo)
add_library(geo::mocks ALIAS geo_mocks)

add_executable(geo_utest
    ${SRCS}
    ${UNIT_SRC_DIR}/manager_test.cpp
    ${UNIT_SRC_DIR}/locator_test.cpp
)
target_include_directories(geo_utest
    PRIVATE
    ${TEST_SRC_DIR}
    ${SRC_DIR}
    ${INC_DIR}/geo
)
target_link_libraries(geo_utest
    PRIVATE
    geo::mocks # Ensure it compiles
    ${PRIVATE_LINKS}
    ${PUBLIC_LINKS}
    gtest_main
    store::mocks
)
target_compile_definitions(geo_utest PRIVATE MMDB_PATH_TEST="${MMDB_PATH_TEST}")

add_executable(geo_ctest
    ${COMPONENT_SRC_DIR}/manager.cpp
)
target_link_libraries(geo_ctest PRIVATE geo gtest_main)
gtest_discover_tests(geo_ctest)

endif(ENGINE_BUILD_TEST)
