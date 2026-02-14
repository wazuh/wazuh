# Defs
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(TEST_DIR ${CMAKE_CURRENT_LIST_DIR}/test)

# Interface
add_library(fastqueue_ifastqueue INTERFACE)
target_include_directories(fastqueue_ifastqueue INTERFACE ${IFACE_DIR})
target_link_libraries(fastqueue_ifastqueue INTERFACE base)
add_library(fastqueue::ifastqueue ALIAS fastqueue_ifastqueue)

# fastqueue
add_library(fastqueue STATIC
  ${SRC_DIR}/cqueue.cpp)

# target_link_libraries(fastqueue
target_include_directories(fastqueue
  PUBLIC
  ${INC_DIR}
)

target_link_libraries(fastqueue
  PUBLIC
  fastqueue::ifastqueue
  unofficial-concurrentqueue::concurrentqueue
)

# Tests
if(ENGINE_BUILD_TEST)
  set(TEST_SRC_DIR ${TEST_DIR}/src)
  set(TEST_SRC_COMPONENT_DIR ${TEST_SRC_DIR}/component)
  set(TEST_SRC_UNIT_DIR ${TEST_SRC_DIR}/unit)
  set(TEST_MOCK_DIR ${TEST_DIR}/mocks)

  # Mocks
  add_library(fastqueue_mocks INTERFACE)
  target_include_directories(fastqueue_mocks INTERFACE ${TEST_MOCK_DIR})
  target_link_libraries(fastqueue_mocks INTERFACE GTest::gmock fastqueue)
  add_library(fastqueue::mocks ALIAS fastqueue_mocks)

  # Component test
  add_executable(fastqueue_ctest
    ${TEST_SRC_COMPONENT_DIR}/cqueue_test.cpp
  )

  target_link_libraries(fastqueue_ctest
    GTest::gtest_main
    base
    fastqueue
    # TODO: Until the indexer connector is unified with the rest of wazuh-manager
    # metrics::mocks
    base::test
  )
  gtest_discover_tests(fastqueue_ctest)

endif(ENGINE_BUILD_TEST)
