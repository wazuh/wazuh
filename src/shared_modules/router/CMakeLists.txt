cmake_minimum_required(VERSION 3.12.4)

project(router)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-DPROMISE_TYPE=PromiseType::NORMAL)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

if(NOT DEFINED SHARED_MODULES)
  get_filename_component(SHARED_MODULES ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
endif()

# Include directories
include_directories(include)

include_directories(${SRC_FOLDER})
include_directories(${SRC_FOLDER}/shared/include)
include_directories(${SRC_FOLDER}/external/rocksdb/include)
include_directories(${SRC_FOLDER}/external/nlohmann)
include_directories(${SRC_FOLDER}/external/cJSON)
include_directories(${SRC_FOLDER}/external/flatbuffers/include)
include_directories(${SRC_FOLDER}/external/simdjson/include)
include_directories(${SHARED_MODULES}/utils)
include_directories(${SHARED_MODULES}/utils/flatbuffers/include)

# Link directories
link_directories(${SRC_FOLDER}/external/flatbuffers/build/)
link_directories(${SRC_FOLDER}/external/simdjson/build/)
link_directories(${SRC_FOLDER}/)

file(GLOB ROUTER_SRC "src/*.cpp")

add_library(router SHARED ${ROUTER_SRC})

target_link_libraries(router PRIVATE gcc_s flatbuffers wazuhext simdjson)

set_target_properties(router PROPERTIES BUILD_RPATH_USE_ORIGIN TRUE
                                        BUILD_RPATH "$ORIGIN/../lib")

if(TARGET compile_schemas_input)
  # If target isn't defined, only this project is being built and not the whole
  # Wazuh project. The schemas must be compiled manually before building this
  # project in that case.
  add_dependencies(router compile_schemas_input)
endif()

if(UNIT_TEST)
  enable_testing()
  add_coverage_libraries(router)
  add_subdirectory(tests)
endif()

add_subdirectory(testtool)
