cmake_minimum_required(VERSION 3.12.4)

project(container_instances_unit_test)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)

link_directories(${SRC_FOLDER}/external/googletest/lib/)

# CONFIGURE_DEPENDS so adding a test file does not need a manual cmake re-run —
# same reasoning as container_baseline_impl/tests.
file(GLOB CONTAINER_INSTANCES_UNIT_TEST_SRC CONFIGURE_DEPENDS "*.cpp")

add_executable(container_instances_unit_test ${CONTAINER_INSTANCES_UNIT_TEST_SRC})

# The tests reach the module's internals directly (cache/, docker/, ...) rather
# than through include/, because what they pin — store transitions, the
# reconcile debounce — has no public surface by design.
target_include_directories(container_instances_unit_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../src
  ${CMAKE_CURRENT_SOURCE_DIR}/../../include
  # The consumer half of the notification channel. Both ends are exercised
  # together because what matters about that transport is the pair's behaviour,
  # not either side in isolation.
  ${SRC_FOLDER}/shared_modules/container_instances_client/include
  # The repo's own IFileSystemWrapper / IFileIOUtils mocks, so the resolver can
  # be driven against a synthetic /proc tree instead of this host's real one —
  # which is unified, and would exercise one of the three hierarchy paths.
  ${SRC_FOLDER}/shared_modules/file_helper/filesystem/tests/mocks
  ${SRC_FOLDER}/shared_modules/file_helper/file_io/tests/mocks
)

target_link_libraries(
  container_instances_unit_test
  container_instances
  debug gtestd debug gtest_maind
  optimized gtest optimized gtest_main
  debug gmockd optimized gmock
  pthread
  dl)

add_test(NAME container_instances_unit_test COMMAND container_instances_unit_test)

set_tests_properties(container_instances_unit_test PROPERTIES LABELS "container_instances")
