cmake_minimum_required(VERSION 3.12.4)

project(content_manager)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

if(NOT DEFINED SHARED_MODULES)
  get_filename_component(SHARED_MODULES ${SRC_FOLDER}/shared_modules/ ABSOLUTE)
endif()

# Include directories
include_directories(include)
include_directories(${SRC_FOLDER})
include_directories(${SRC_FOLDER}/shared/include)
include_directories(${SRC_FOLDER}/external/cJSON)
include_directories(${SRC_FOLDER}/external/nlohmann)
include_directories(${SRC_FOLDER}/external/curl/include/curl)
include_directories(${SRC_FOLDER}/external/rocksdb/include)
include_directories(${SRC_FOLDER}/external/zlib/)
include_directories(${SRC_FOLDER}/external/zlib/contrib/)

include_directories(${SHARED_MODULES})
include_directories(${SHARED_MODULES}/utils)
include_directories(${SHARED_MODULES}/content_manager/src/components)
include_directories(${SHARED_MODULES}/indexer_connector/include)

# Link directories
link_directories(${SRC_FOLDER})
link_directories(${SRC_FOLDER}/build/lib)
link_directories(${SHARED_MODULES}/indexer_connector/build)
link_directories(${SRC_FOLDER}/external/rocksdb/build/)
link_directories(${SRC_FOLDER}/external/zlib/)
link_directories(${SRC_FOLDER}/external/zlib/contrib/minizip/)

file(GLOB CONTENT_DOWNLOAD_SRC "src/*.cpp")

add_library(content_manager SHARED ${CONTENT_DOWNLOAD_SRC})

# flatbuffers was linked but never referenced: grepping the module for it returns nothing. Dropping
# it matters beyond tidiness -- every host that links this library inherited a DT_NEEDED on a
# library it does not use.
target_link_libraries(content_manager PRIVATE gcc_s wazuhext
                                              rocksdb indexer_connector)

# PUBLIC so a host outside this tree (the Engine) gets the contract headers by linking the target,
# instead of hard-coding a relative path to them.
# ${SHARED_MODULES}/utils is here for one header: contentManager.hpp derives ContentModule from
# Singleton<>. Nothing else in include/ reaches outside these three directories, and the
# content_manager_public_abi_c17 target below is compiled with exactly this set so a fourth
# dependency cannot creep in unnoticed.
target_include_directories(content_manager PUBLIC
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
                           $<BUILD_INTERFACE:${SRC_FOLDER}/external/nlohmann>
                           $<BUILD_INTERFACE:${SHARED_MODULES}/utils>)

set_target_properties(content_manager PROPERTIES BUILD_RPATH_USE_ORIGIN TRUE
                                                 BUILD_RPATH "$ORIGIN/../lib")

if(UNIT_TEST)
  enable_testing()
  add_coverage_libraries(content_manager)
  add_subdirectory(tests)

  # Compiles the public headers alone, under C++17, with ONLY the include directories a foreign
  # host gets. Two things fail this target and nothing else catches either of them: a public header
  # reaching for a C++20 feature (the Engine's own libraries are C++17), and a private header
  # (rocksDBWrapper.hpp, contentModuleFacade.hpp, onDemandManager.hpp) leaking into include/.
  add_library(content_manager_public_abi_c17 OBJECT tests/abi/publicHeaders17.cpp)
  set_target_properties(content_manager_public_abi_c17 PROPERTIES CXX_STANDARD 17
                                                                  CXX_STANDARD_REQUIRED ON)
  # set_property REPLACES the include directories this target inherited from the directory-scoped
  # include_directories() calls above. target_include_directories would only ADD to them, and the
  # guard would then pass no matter what leaked.
  set_property(TARGET content_manager_public_abi_c17 PROPERTY INCLUDE_DIRECTORIES
               ${CMAKE_CURRENT_LIST_DIR}/include
               ${SRC_FOLDER}/external/nlohmann
               ${SHARED_MODULES}/utils)
endif()

add_subdirectory(testtool)
