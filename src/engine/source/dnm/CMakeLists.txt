# Defs
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

add_library(dnm_idnm INTERFACE)
target_include_directories(dnm_idnm INTERFACE ${IFACE_DIR})
add_library(dnm::idnm ALIAS dnm_idnm)

# Library definition
add_library(dnm STATIC
  ${SRC_DIR}/DocumentManager.cpp
  ${SRC_DIR}/docStorage/fileDriver.cpp
)

target_include_directories(dnm
  PUBLIC
  ${INC_DIR}
  PRIVATE
  ${SRC_DIR}
  ${INC_DIR}/dnm
)

target_link_libraries(dnm
  PUBLIC
  dnm::idnm
  PRIVATE
  base
)

# Tests
if(ENGINE_BUILD_TEST)
  set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
  set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)

  add_library(dnm_mocks INTERFACE)

  target_include_directories(dnm_mocks INTERFACE ${TEST_MOCK_DIR})
  target_link_libraries(dnm_mocks INTERFACE gmock dnm::idnm)
  add_library(dnm::mocks ALIAS dnm_mocks)

  add_executable(dnm_test
    ${TEST_SRC_DIR}/DocumentNamespaceManager_test.cpp
  )

  target_include_directories(dnm_test
    PRIVATE
    ${TEST_SRC_DIR}
  )

  target_link_libraries(dnm_test gtest_main base dnm store::mocks)
  gtest_discover_tests(dnm_test)
endif(ENGINE_BUILD_TEST)
