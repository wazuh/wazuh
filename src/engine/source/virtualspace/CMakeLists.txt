# Defs
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

add_library(virtualspace_ivirtualspace INTERFACE)
target_include_directories(virtualspace_ivirtualspace INTERFACE ${IFACE_DIR})
add_library(virtualspace::ivirtualspace ALIAS virtualspace_ivirtualspace)


# Library definition
add_library(virtualspace STATIC
  ${SRC_DIR}/virtualspace.cpp
)

target_include_directories(virtualspace
PUBLIC
  ${INC_DIR}
PRIVATE
  ${SRC_DIR}
  ${INC_DIR}/virtualspace
)

target_link_libraries(virtualspace
PUBLIC
    virtualspace::ivirtualspace
PRIVATE
    base store::istore
)

# Tests
if(ENGINE_BUILD_TEST)
set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)

add_library(virtualspace_mocks INTERFACE)

target_include_directories(virtualspace_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(virtualspace_mocks INTERFACE gmock virtualspace::ivirtualspace)
add_library(virtualspace::mocks ALIAS virtualspace_mocks)

add_executable(virtualspace_test
  ${TEST_SRC_DIR}/virtualspace_test.cpp
)

target_include_directories(virtualspace_test
    PRIVATE
    ${TEST_SRC_DIR}
)

target_link_libraries(virtualspace_test gtest_main base virtualspace store::mocks)
gtest_discover_tests(virtualspace_test)

endif(ENGINE_BUILD_TEST)
