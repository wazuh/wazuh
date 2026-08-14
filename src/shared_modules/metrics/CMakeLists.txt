cmake_minimum_required(VERSION 3.12.4)

project(wazuh_metrics CXX)

# Deliberately NOT named/aliased fastmetrics*: the engine's fastmetrics targets
# live in this same build tree, and a second Manager under the same namespace
# would be a silent ODR trap for any test binary that links both worlds.
add_library(wazuh_metrics STATIC src/manager.cpp src/jsonDump.cpp)

target_include_directories(wazuh_metrics PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Minimum 17 (the consumers include a strict-C++17 module); compiles unchanged
# under the tree-wide 20.
target_compile_features(wazuh_metrics PUBLIC cxx_std_17)

# Static lib linked into shared libs (inventory_sync_server, remoted_module).
set_target_properties(wazuh_metrics PROPERTIES POSITION_INDEPENDENT_CODE ON)

# rapidjson stays PRIVATE and confined to jsonDump.cpp: no public header names
# it, so consumers' unit tests never need its include path.
target_link_libraries(wazuh_metrics PRIVATE ext_rapidjson)

if(UNIT_TEST)
  enable_testing()
  add_coverage_libraries(wazuh_metrics)
  add_subdirectory(test)
endif()
