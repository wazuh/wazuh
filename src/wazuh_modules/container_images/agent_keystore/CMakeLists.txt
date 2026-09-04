cmake_minimum_required(VERSION 3.12.4)

project(agent_keystore)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(${SRC_FOLDER}/external/openssl/include/)
include_directories(${SRC_FOLDER}/shared_modules/common/)
include_directories(${SRC_FOLDER}/shared_modules/utils/)
include_directories(${SRC_FOLDER}/shared/include/)
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../container_images_impl/include)

link_directories(${CMAKE_BINARY_DIR}/lib)

add_executable(wazuh-agent-keystore main.cpp)

# ContainerImagesImpl carries the store. Only the objects the tool references are pulled
# in, so this does not drag the inventory or DBSync into the binary.
target_link_libraries(wazuh-agent-keystore PRIVATE ContainerImagesImpl wazuhext)

set_target_properties(
  wazuh-agent-keystore
  PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${SRC_FOLDER}/build/bin
             BUILD_RPATH_USE_ORIGIN TRUE
             BUILD_RPATH "$ORIGIN/../lib")
