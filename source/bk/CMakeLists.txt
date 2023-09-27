# Dependencies
CPMAddPackage(
  NAME taskflow
  GITHUB_REPOSITORY taskflow/taskflow
  GIT_TAG v3.6.0
  VERSION 3.6.0
  EXCLUDE_FROM_ALL YES
)


# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

## Interface
add_library(bk_ibk INTERFACE)
target_include_directories(bk_ibk INTERFACE ${IFACE_DIR})
target_link_libraries(bk_ibk INTERFACE base) # Base for expression
add_library(bk::ibk ALIAS bk_ibk)

# TaskFlow
set(TASKF_SRC_DIR ${SRC_DIR}/taskf)

add_library(bk_taskf STATIC
    ${TASKF_SRC_DIR}/controller.cpp
)
target_include_directories(bk_taskf
    PUBLIC
    ${INC_DIR}
    ${taskflow_SOURCE_DIR}

    PRIVATE
    ${TASKF_SRC_DIR}
    ${INC_DIR}/bk/taskf
)
target_link_libraries(bk_taskf PUBLIC bk::ibk)
add_library(bk::taskf ALIAS bk_taskf)

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
target_link_libraries(tfbk_utest gtest_main bk::taskf)
gtest_discover_tests(tfbk_utest)

endif(ENGINE_BUILD_TEST)
