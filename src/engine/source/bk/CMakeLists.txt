# Dependencies
CPMAddPackage(
  NAME taskflow
  GITHUB_REPOSITORY taskflow/taskflow
  GIT_TAG v3.6.0
  VERSION 3.6.0
  EXCLUDE_FROM_ALL YES
)


# Defs
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

## Interface
add_library(backend_ibackend INTERFACE)
target_include_directories(backend_ibackend INTERFACE ${IFACE_DIR})
target_link_libraries(backend_ibackend INTERFACE base) # Base for expression
add_library(backend::ibackend ALIAS backend_ibackend)

## TaskFlow Backend
add_library(tfbk STATIC
    ${SRC_DIR}/tfbk.cpp
)
target_include_directories(tfbk
    PUBLIC
    ${INC_DIR}
    ${taskflow_SOURCE_DIR}
)
target_link_libraries(tfbk PUBLIC backend::ibackend)
add_library(backend::tfbk ALIAS tfbk)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
# set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

## Mocks
# add_library(backend_mocks INTERFACE)
# target_include_directories(backend_mocks INTERFACE ${TEST_MOCK_DIR})
# target_link_libraries(backend_mocks INTERFACE gmock backend::ibackend)
# add_library(backend::mocks ALIAS backend_mocks)


## TaskFlow Backend component test
# add_executable(backend_ctest
#     ${COMPONENT_SRC_DIR}/backend_test.cpp
# )
# target_link_libraries(backend_ctest gtest_main backend::fileDriver backend)
# gtest_discover_tests(backend_ctest)

## TaskFlow Backend unit test
add_executable(tfbk_utest
    ${UNIT_SRC_DIR}/tfbk_test.cpp
)
target_link_libraries(tfbk_utest gtest_main backend::tfbk)
gtest_discover_tests(tfbk_utest)

endif(ENGINE_BUILD_TEST)
