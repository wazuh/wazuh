cmake_minimum_required(VERSION 3.12.4)

project(keystore)

enable_testing()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "-fPIC")

if(FSANITIZE)
  set(CMAKE_CXX_FLAGS_DEBUG "-g -fsanitize=address,leak,undefined")
endif(FSANITIZE)

set(ORIGINAL_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${SRC_FOLDER})

file(GLOB KEYSTORE_SRC
    "src/keyStore.cpp"
    )

if (NOT SRC_FOLDER)
    get_filename_component(SRC_FOLDER     ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

if (NOT SHARED_MODULES)
    get_filename_component(SHARED_MODULES ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
endif()

include_directories(include)
include_directories(src)
include_directories(${SRC_FOLDER}/external/rocksdb/include)
include_directories(${SRC_FOLDER}/external/openssl/include)
include_directories(${SRC_FOLDER}/external/cJSON)
include_directories(${SHARED_MODULES}/utils)
include_directories(${SHARED_MODULES}/common)

link_directories(${SRC_FOLDER})
link_directories(${SRC_FOLDER}/external/rocksdb/build)

add_library(keystore STATIC ${KEYSTORE_SRC})

target_link_libraries(keystore rocksdb wazuhext)

add_executable(wazuh-keystore src/main.cpp)

target_link_libraries(wazuh-keystore keystore)

set_target_properties(wazuh-keystore PROPERTIES
    BUILD_RPATH_USE_ORIGIN TRUE
    BUILD_RPATH "$ORIGIN/../lib"
)

add_subdirectory(testtool)
