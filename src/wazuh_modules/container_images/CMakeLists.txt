cmake_minimum_required(VERSION 3.12.4)

project(container_images)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

set(CMAKE_CXX_FLAGS
    "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -pthread"
)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if(APPLE)
  set(CMAKE_MACOSX_RPATH 1)
endif(APPLE)

add_subdirectory(container_images_impl)

include_directories(${SRC_FOLDER}/shared/include/)
include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(${SRC_FOLDER}/external/cJSON/)
include_directories(${SRC_FOLDER}/shared_modules/utils/)
include_directories(${SRC_FOLDER}/shared_modules/common/)
include_directories(${SRC_FOLDER}/wazuh_modules/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/container_images_impl/include)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  link_directories(${CMAKE_BINARY_DIR}/bin)
else()
  link_directories(${CMAKE_BINARY_DIR}/lib)
endif()
link_directories(${SRC_FOLDER})
link_directories(${SRC_FOLDER}/build/lib)
link_directories(${SRC_FOLDER}/external/cJSON/)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DWIN32=1 -D_WIN32_WINNT=0x600 -DWIN_EXPORT)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

file(GLOB CONTAINER_IMAGES_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

add_library(container_images SHARED ${CONTAINER_IMAGES_SRC} ${RESOURCE_OBJ_DLL})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set_target_properties(
    container_images
    PROPERTIES PREFIX ""
               SUFFIX ".dll"
               LINK_FLAGS "-Wl,--add-stdcall-alias"
               POSITION_INDEPENDENT_CODE 0)
elseif(UNIX AND NOT APPLE)
  string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,-rpath=$ORIGIN")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

target_link_libraries(container_images PRIVATE ContainerImagesImpl wazuhext)
