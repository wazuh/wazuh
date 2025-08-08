cmake_minimum_required(VERSION 3.12.4)

project(router)

enable_testing()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-DPROMISE_TYPE=PromiseType::NORMAL)

if (NOT SRC_FOLDER)
    get_filename_component(SRC_FOLDER     ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

if (NOT SHARED_MODULES)
    get_filename_component(SHARED_MODULES ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
endif()

# Include directories
include_directories(include)

include_directories(${SRC_FOLDER})
include_directories(${SRC_FOLDER}/headers)
include_directories(${SRC_FOLDER}/external/rocksdb/include)
include_directories(${SRC_FOLDER}/external/nlohmann)
include_directories(${SRC_FOLDER}/external/cJSON)
include_directories(${SRC_FOLDER}/external/flatbuffers/include)
include_directories(${SHARED_MODULES}/utils)

# Link directories
link_directories(${SRC_FOLDER}/external/flatbuffers/build/)
link_directories(${SRC_FOLDER}/)

file(GLOB ROUTER_SRC
    "src/*.cpp"
    )

add_library(router SHARED
    ${ROUTER_SRC}
    )

target_link_libraries(router gcc_s flatbuffers wazuhext)

set_target_properties(router PROPERTIES
        BUILD_RPATH_USE_ORIGIN TRUE
        BUILD_RPATH "$ORIGIN/../lib"
)

add_subdirectory(testtool)
if(UNIT_TEST)
    add_subdirectory(tests)
endif()
