# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR   ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR   ${CMAKE_CURRENT_LIST_DIR}/include)

# INTERFACE
add_library(iocsync_iiocsync INTERFACE)
target_include_directories(iocsync_iiocsync INTERFACE ${IFACE_DIR})
target_link_libraries(iocsync_iiocsync INTERFACE base)
add_library(iocsync::iiocsync ALIAS iocsync_iiocsync)

# Implementation
add_library(iocsync_iocsync STATIC
    ${SRC_DIR}/iocsync.cpp
)
target_include_directories(iocsync_iocsync
    PUBLIC
    ${INC_DIR}
    PRIVATE
    ${SRC_DIR}
)
target_link_libraries(iocsync_iocsync
    PUBLIC
    iocsync::iiocsync
    PRIVATE
    wIndexerConnector::iwIndexerConnector
    store::istore
    kvdbioc::ikvdb
)
add_library(iocsync::iocsync ALIAS iocsync_iocsync)

# Tests
# if(ENGINE_BUILD_TEST)

# set(TEST_SRC_DIR   ${CMAKE_CURRENT_LIST_DIR}/test/src)
# set(UNIT_SRC_DIR   ${TEST_SRC_DIR}/unit)
# set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)
# set(TEST_MOCK_DIR  ${CMAKE_CURRENT_LIST_DIR}/test/mocks)

# # Mocks
# add_library(kvdbiocsync_mocks INTERFACE)
# target_include_directories(kvdbiocsync_mocks INTERFACE ${TEST_MOCK_DIR})
# target_link_libraries(kvdbiocsync_mocks INTERFACE GTest::gmock kvdbiocsync::ikvdb)
# add_library(kvdbiocsync::mocks ALIAS kvdbiocsync_mocks)

# # Unit tests
# add_executable(kvdbiocsync_utest
#     ${UNIT_SRC_DIR}/kvdb_handler_test.cpp
#     ${UNIT_SRC_DIR}/kvdb_manager_test.cpp
# )
# target_link_libraries(kvdbiocsync_utest
#     PRIVATE
#         GTest::gtest_main
#         GTest::gmock
#         kvdbiocsync::kvdb
#         kvdbiocsync::mocks
# )
# target_include_directories(kvdbiocsync_utest PRIVATE ${SRC_DIR})
# gtest_discover_tests(kvdbiocsync_utest)

# # Component tests
# add_executable(kvdbiocsync_ctest
#     ${COMPONENT_SRC_DIR}/kvdb_test.cpp
# )
# target_link_libraries(kvdbiocsync_ctest
#     PRIVATE
#         GTest::gtest_main
#         GTest::gmock
#         kvdbiocsync::kvdb
#         store::mocks
# )
# gtest_discover_tests(kvdbiocsync_ctest)

# endif(ENGINE_BUILD_TEST)
