# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

####################################################################################################
# Dependencies -- assuming cpm is available
####################################################################################################
CPMAddPackage(
    NAME libmaxminddb
    GITHUB_REPOSITORY maxmind/libmaxminddb
    GIT_TAG 1.9.1
    OPTIONS
    "BUILD_SHARED_LIBS OFF"
    "BUILD_TESTING OFF"
)

# Interface
add_library(mmdb_immdb INTERFACE)
target_include_directories(mmdb_immdb INTERFACE ${IFACE_DIR})
target_link_libraries(mmdb_immdb INTERFACE base)
add_library(mmdb::immdb ALIAS mmdb_immdb)

# Implementation
add_library(mmdb_mmdb STATIC
    ${SRC_DIR}/result.cpp
    ${SRC_DIR}/handler.cpp
)


target_include_directories(mmdb_mmdb
    PUBLIC
    ${INC_DIR}

    PRIVATE
    ${SRC_DIR}
)
target_link_libraries(mmdb_mmdb
    PUBLIC
    mmdb::immdb
    base

    PRIVATE
    maxminddb::maxminddb
)
add_library(mmdb::mmdb ALIAS mmdb_mmdb)

# Tests
if(ENGINE_BUILD_TEST)
    set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
    set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
    set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
    set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

    # Mocks
    # add_library(mmdb_mocks INTERFACE)
    # target_include_directories(mmdb_mocks INTERFACE ${TEST_MOCK_DIR})
    # target_link_libraries(mmdb_mocks INTERFACE gmock mmdb::immdb)
    # add_library(mmdb::mocks ALIAS mmdb_mocks)

    # mmdb component test
    # add_executable(mmdb_ctest
    #     ${COMPONENT_SRC_DIR}/mmdb_test.cpp
    # )
    # target_include_directories(mmdb_ctest PRIVATE ${SRC_DIR})
    # target_link_libraries(mmdb_ctest
    #     gtest_main
    #     base
    #     mmdb::mmdb
    # )

    # mmdb unit test
    add_executable(mmdb_utest
        ${UNIT_SRC_DIR}/handler_test.cpp
    #    ${UNIT_SRC_DIR}/mmdb_test.cpp
    )
    target_include_directories(mmdb_utest PRIVATE ${SRC_DIR})
    target_link_libraries(mmdb_utest
        gtest_main
        mmdb::mmdb
        maxminddb::maxminddb
    )
    gtest_discover_tests(mmdb_utest mmdb_ctest)
endif(ENGINE_BUILD_TEST)
