cmake_minimum_required(VERSION 3.12.4)

project(keystore_server CXX)

# Colocate the .so next to the other manager shared libs so modulesd's runtime rpath
# ($ORIGIN/../lib) resolves it.
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

file(GLOB KEYSTORE_SERVER_SRC "src/*.cpp")

add_library(keystore_server SHARED ${KEYSTORE_SERVER_SRC})

target_include_directories(
  keystore_server
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${SRC_FOLDER}/shared_modules/utils # socketServer.hpp, loggerHelper.h
          ${SRC_FOLDER}/shared_modules/common # commonDefs.h
          ${SRC_FOLDER}/shared_modules/keystore/include
          ${SRC_FOLDER}/external/cJSON # cJSON.h (pulled by commonDefs.h)
          ${SRC_FOLDER}/external/nlohmann) # json.hpp

# keystore is STATIC and carries its own rocksdb/wazuhext link requirements transitively.
target_link_libraries(keystore_server PRIVATE pthread keystore wazuhext)

set_target_properties(keystore_server PROPERTIES BUILD_RPATH_USE_ORIGIN TRUE BUILD_RPATH "$ORIGIN/../lib")

if(UNIT_TEST)
  enable_testing()
  add_coverage_libraries(keystore_server)
  add_subdirectory(test)
endif()
