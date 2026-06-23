cmake_minimum_required(VERSION 3.12.4)

project(ContainerImagesImpl)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DWIN32=1)
endif()

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

link_directories(${SRC_FOLDER})
link_directories(${SRC_FOLDER}/build/lib)
link_directories(${CMAKE_BINARY_DIR}/lib)

include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(${SRC_FOLDER}/shared/include/)
include_directories(${SRC_FOLDER}/shared_modules/common/)
include_directories(${SRC_FOLDER}/shared_modules/utils/)

add_library(
  ContainerImagesImpl STATIC
  src/container_images_impl.cpp
  src/local_image_reader.cpp)

set_target_properties(ContainerImagesImpl PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(
  ContainerImagesImpl
  PUBLIC include)

target_link_libraries(ContainerImagesImpl PRIVATE wazuhext)

if(UNIT_TEST AND ("${TARGET}" STREQUAL "agent" OR "${TARGET}" STREQUAL
                                                  "winagent"))
  enable_testing()
  add_coverage_libraries(ContainerImagesImpl)
  add_subdirectory(tests)
endif()
