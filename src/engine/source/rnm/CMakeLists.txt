# Defs
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

add_library(rnm_irnm INTERFACE)
target_include_directories(rnm_irnm INTERFACE ${IFACE_DIR})
add_library(rnm::irnm ALIAS rnm_irnm)


# Library definition
add_library(rnm STATIC
  ${SRC_DIR}/resourceNamespaceManager.cpp
)

target_include_directories(rnm
PUBLIC
  ${INC_DIR}
PRIVATE
  ${SRC_DIR}
  ${INC_DIR}/rnm
)

target_link_libraries(rnm
PUBLIC
    rnm::irnm
PRIVATE
    base store::istore
)

# Tests
if(ENGINE_BUILD_TEST)
set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)

add_library(rnm_mocks INTERFACE)

target_include_directories(rnm_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(rnm_mocks INTERFACE gmock rnm::irnm)
add_library(rnm::mocks ALIAS rnm_mocks)

add_executable(rnm_test
  ${TEST_SRC_DIR}/resourceNamespaceManager_test.cpp
)

target_include_directories(rnm_test
    PRIVATE
    ${TEST_SRC_DIR}
)

target_link_libraries(rnm_test gtest_main base rnm store::mocks)
gtest_discover_tests(rnm_test)

endif(ENGINE_BUILD_TEST)
