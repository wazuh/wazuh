# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)


# INTERFACE
add_library(dumper_iface INTERFACE)
target_include_directories(dumper_iface INTERFACE ${IFACE_DIR})
target_link_libraries(dumper_iface INTERFACE base streamlogger::istreamlogger)
add_library(dumper::iface ALIAS dumper_iface)

# Implementation
add_library(dumper_dumper STATIC
  ${SRC_DIR}/dumper.cpp
)

target_include_directories(dumper_dumper
  PUBLIC
  ${INC_DIR}
)
target_link_libraries(dumper_dumper
  PUBLIC
  dumper::iface
)

add_library(dumper::dumper ALIAS dumper_dumper)

if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

# Testing mocks
add_library(dumper_mocks INTERFACE)
target_include_directories(dumper_mocks INTERFACE ${TEST_MOCK_DIR}
)
target_link_libraries(dumper_mocks INTERFACE dumper_iface)
add_library(dumper::mocks ALIAS dumper_mocks)

# Testing
add_executable(dumper_utest
    ${UNIT_SRC_DIR}/dumper_test.cpp
)
target_include_directories(dumper_utest
    PRIVATE
    ${UNIT_SRC_DIR}
)
target_link_libraries(dumper_utest
    PRIVATE
    dumper::dumper
    GTest::gmock
    GTest::gtest_main
    dumper::mocks
    streamlogger::mocks
)
gtest_discover_tests(dumper_utest)

endif(ENGINE_BUILD_TEST)
