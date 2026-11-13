if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

include_directories(
  ${SRC_FOLDER}/external/googletest/googletest/include/
  ${SRC_FOLDER}/external/googletest/googlemock/include/
  ${SRC_FOLDER}/external/nlohmann/
  ${SRC_FOLDER}/external/zlib/
  ${SRC_FOLDER}/external/zstd/lib/
  ${SRC_FOLDER}/external/sqlite/
  ${SRC_FOLDER}/external/curl/include/
  ${SRC_FOLDER}/data_provider/src/packages/
  ${SRC_FOLDER}/shared_modules/dbsync/include/
  ${SRC_FOLDER}/wazuh_modules/container_images/container_images_impl/include
  ${SRC_FOLDER}/wazuh_modules/container_images/container_images_impl/src)

link_directories(${SRC_FOLDER}/external/googletest/lib/)

link_libraries(
  debug
  gtestd
  debug
  gmockd
  debug
  gtest_maind
  debug
  gmock_maind
  optimized
  gtest
  optimized
  gmock
  optimized
  gtest_main
  optimized
  gmock_main)

# Resolve both shared libraries from the main build's lib directory. A second copy of
# libdbsync.so also exists under shared_modules/dbsync/build/lib; linking that one puts a
# mismatched build ahead in the test's RUNPATH and crashes at process exit. Always use the
# copy the agent itself links (${CMAKE_BINARY_DIR}/lib).
find_library(
  DBSYNC_LIB dbsync
  HINTS ${CMAKE_BINARY_DIR}/lib
  NO_DEFAULT_PATH)
if(NOT DBSYNC_LIB)
  set(DBSYNC_LIB dbsync)
endif()

add_executable(container_images_unit_test container_images_test.cpp
                                          package_extraction_test.cpp
                                          credential_store_test.cpp
                                          platform_test.cpp
                                          registry_reader_test.cpp
                                          registry_test.cpp
                                          transport_test.cpp)
# The DB tests exercise a real DBSync instance, so the real libraries are linked
# (not mocks). wazuhext provides the hash/string helpers.
target_link_libraries(container_images_unit_test
  PRIVATE ContainerImagesImpl ${DBSYNC_LIB} wazuhext ext_zstd)

# Two libdbsync.so exist (the agent's under build/lib and a standalone one under
# shared_modules/dbsync/build/lib). They are not byte-identical and mixing them crashes the
# test process at exit. Force the loader to resolve every shared library from the agent build
# directory so the test uses the same dbsync the module links at runtime.
set_target_properties(container_images_unit_test PROPERTIES
  BUILD_RPATH "${CMAKE_BINARY_DIR}/lib"
  SKIP_BUILD_RPATH OFF)

add_test(NAME ContainerImagesTest COMMAND container_images_unit_test)

set_tests_properties(ContainerImagesTest PROPERTIES LABELS "container_images")
