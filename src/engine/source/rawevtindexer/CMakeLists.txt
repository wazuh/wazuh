# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR   ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR   ${CMAKE_CURRENT_LIST_DIR}/include)

# INTERFACE
add_library(rawevtindexer_irawindexer INTERFACE)
target_include_directories(rawevtindexer_irawindexer INTERFACE ${IFACE_DIR})
target_link_libraries(rawevtindexer_irawindexer INTERFACE base)
add_library(rawevtindexer::irawindexer ALIAS rawevtindexer_irawindexer)

# Implementation
add_library(rawevtindexer_rawevtindexer STATIC
    ${SRC_DIR}/raweventindexer.cpp
)
target_include_directories(rawevtindexer_rawevtindexer
    PUBLIC
        ${INC_DIR}
    PRIVATE
        ${SRC_DIR}
)
target_link_libraries(rawevtindexer_rawevtindexer
    PUBLIC
        rawevtindexer::irawindexer
        base
        wIndexerConnector::iwIndexerConnector
)
add_library(rawevtindexer::rawevtindexer ALIAS rawevtindexer_rawevtindexer)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR  ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR  ${TEST_SRC_DIR}/unit)
set(COMP_SRC_DIR  ${TEST_SRC_DIR}/component)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)

# Mocks
add_library(rawevtindexer_mocks INTERFACE)
target_include_directories(rawevtindexer_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(rawevtindexer_mocks INTERFACE GTest::gmock rawevtindexer::irawindexer wIndexerConnector::mocks)
add_library(rawevtindexer::mocks ALIAS rawevtindexer_mocks)

# Unit tests
add_executable(rawevtindexer_utest
    ${UNIT_SRC_DIR}/raweventindexer_test.cpp
)
target_link_libraries(rawevtindexer_utest
    PRIVATE
        GTest::gtest_main
        GTest::gmock
        rawevtindexer::rawevtindexer
        rawevtindexer::mocks
)
target_include_directories(rawevtindexer_utest PRIVATE ${SRC_DIR})
gtest_discover_tests(rawevtindexer_utest)

# Component tests
add_executable(rawevtindexer_ctest
    ${COMP_SRC_DIR}/raweventindexer_test.cpp
)
target_link_libraries(rawevtindexer_ctest
    PRIVATE
        GTest::gtest_main
        GTest::gmock
        rawevtindexer::rawevtindexer
        rawevtindexer::mocks
)
target_include_directories(rawevtindexer_ctest PRIVATE ${SRC_DIR})
gtest_discover_tests(rawevtindexer_ctest)

endif(ENGINE_BUILD_TEST)
