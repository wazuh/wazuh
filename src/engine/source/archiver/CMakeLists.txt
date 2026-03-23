# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)


# INTERFACE
add_library(archiver_iface INTERFACE)
target_include_directories(archiver_iface INTERFACE ${IFACE_DIR})
target_link_libraries(archiver_iface INTERFACE base streamlogger::istreamlogger)
add_library(archiver::iface ALIAS archiver_iface)

# Implementation
add_library(archiver_archive STATIC
  ${SRC_DIR}/archiver.cpp
)

target_include_directories(archiver_archive
  PUBLIC
  ${INC_DIR}
)
target_link_libraries(archiver_archive
  PUBLIC
  archiver::iface
)

add_library(archiver::archive ALIAS archiver_archive)

if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

# Testing mocks
add_library(archiver_mocks INTERFACE)
target_include_directories(archiver_mocks INTERFACE ${TEST_MOCK_DIR}
)
target_link_libraries(archiver_mocks INTERFACE archiver_iface)
add_library(archiver::mocks ALIAS archiver_mocks)

# Testing
add_executable(archiver_utest
    ${UNIT_SRC_DIR}/archiver_test.cpp
)
target_include_directories(archiver_utest
    PRIVATE
    ${UNIT_SRC_DIR}
)
target_link_libraries(archiver_utest
    PRIVATE
    archiver::archive
    GTest::gmock
    GTest::gtest_main
    archiver::mocks
    streamlogger::mocks
)
gtest_discover_tests(archiver_utest)

endif(ENGINE_BUILD_TEST)
