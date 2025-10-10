cmake_minimum_required(VERSION 3.12.4)

project(indexer_connector)

enable_testing()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-DPROMISE_TYPE=PromiseType::NORMAL)

if (NOT SRC_FOLDER)
    get_filename_component(SRC_FOLDER     ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

if (NOT SHARED_MODULES)
    get_filename_component(SHARED_MODULES ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
endif()

# Source files
file(GLOB INDEXER_CONNECTOR_SRC "src/*.cpp")

# Create library
add_library(indexer_connector SHARED ${INDEXER_CONNECTOR_SRC})

# Include directories - PUBLIC for headers needed by consumers
target_include_directories(indexer_connector
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${SRC_FOLDER}/external/simdjson/include # PUBLIC because .hpp includes it
    PRIVATE
    ${SRC_FOLDER}/external/cJSON
    ${SRC_FOLDER}/external/nlohmann
    ${SRC_FOLDER}/external/openssl/include
    ${SHARED_MODULES}/utils
    ${SHARED_MODULES}/common
    ${SHARED_MODULES}/http-request/include
    ${SHARED_MODULES}/keystore/include
)

# Link directories
target_link_directories(indexer_connector
    PRIVATE
    ${SRC_FOLDER}/external/rocksdb/build
    ${SRC_FOLDER}/external/simdjson/build
    ${SHARED_MODULES}/http-request/build
    ${SHARED_MODULES}/keystore/build
)

# Link libraries
target_link_libraries(indexer_connector
    PRIVATE
    rocksdb
    urlrequest
    gcc_s
    wazuhext
    keystore
    simdjson
)

set_target_properties(indexer_connector PROPERTIES
        BUILD_RPATH_USE_ORIGIN TRUE
        BUILD_RPATH "$ORIGIN/../lib"
)

add_subdirectory(testtool)
if(UNIT_TEST)
    add_subdirectory(tests)
endif()
