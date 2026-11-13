cmake_minimum_required(VERSION 3.12.4)

project(wm_indexer_runtime CXX)

# Next to the other manager shared libs so modulesd's runtime rpath ($ORIGIN/../lib) resolves it. modulesd loads it
# with so_get_module_handle: nothing in C links this library.
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

file(GLOB WM_INDEXER_RUNTIME_SRC "src/*.cpp")

# The objects are shared by the .so and by the unit tests, which drive the internal test seam (wmIndexerRuntime.hpp).
add_library(wm_indexer_runtime_objects OBJECT ${WM_INDEXER_RUNTIME_SRC})
set_target_properties(wm_indexer_runtime_objects PROPERTIES POSITION_INDEPENDENT_CODE ON)
# Only the five wmir_* functions (WMIR_API) are exported; the test seams, Keystore and everything else stay local.
target_compile_options(wm_indexer_runtime_objects PRIVATE -fvisibility=hidden -fvisibility-inlines-hidden)
target_include_directories(
  wm_indexer_runtime_objects
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src
  PRIVATE ${SRC_FOLDER}/shared_modules/keystore/include ${SRC_FOLDER}/shared_modules/common
          ${SRC_FOLDER}/external/cJSON ${SRC_FOLDER}/external/nlohmann)
target_link_libraries(wm_indexer_runtime_objects PUBLIC indexer_client)

add_library(wm_indexer_runtime SHARED $<TARGET_OBJECTS:wm_indexer_runtime_objects>)
target_link_libraries(wm_indexer_runtime PRIVATE indexer_client keystore wazuhext pthread)
# --exclude-libs localizes whatever arrives from static archives (keystore and its dependencies).
target_link_options(wm_indexer_runtime PRIVATE "LINKER:--exclude-libs,ALL")
set_target_properties(wm_indexer_runtime PROPERTIES BUILD_RPATH_USE_ORIGIN TRUE BUILD_RPATH "$ORIGIN/../lib")

if(UNIT_TEST)
  enable_testing()
  add_subdirectory(tests)
endif()
