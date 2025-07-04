cmake_minimum_required(VERSION 3.12.4)

project(content_manager)

enable_testing()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (NOT SRC_FOLDER)
    get_filename_component(SRC_FOLDER     ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

if (NOT SHARED_MODULES)
    get_filename_component(SHARED_MODULES ${SRC_FOLDER}/shared_modules/ ABSOLUTE)
endif()

# Include directories
include_directories(include)

include_directories(${SRC_FOLDER})
include_directories(${SRC_FOLDER}/headers)
include_directories(${SRC_FOLDER}/external/cJSON)
include_directories(${SRC_FOLDER}/external/nlohmann)
include_directories(${SRC_FOLDER}/external/curl/include/curl)
include_directories(${SRC_FOLDER}/external/lzma/src/liblzma/api)
include_directories(${SRC_FOLDER}/external/rocksdb/include)
include_directories(${SRC_FOLDER}/external/zlib/)
include_directories(${SRC_FOLDER}/external/zlib/contrib/)

include_directories(${SHARED_MODULES})
include_directories(${SHARED_MODULES}/utils)
include_directories(${SHARED_MODULES}/router/include)
include_directories(${SHARED_MODULES}/http-request/include)
include_directories(${SHARED_MODULES}/content_manager/src/components)

# Link directories
link_directories(${SRC_FOLDER})
link_directories(${SRC_FOLDER}/external/lzma/build/)
link_directories(${SRC_FOLDER}/external/rocksdb/build/)
link_directories(${SRC_FOLDER}/external/zlib/)
link_directories(${SRC_FOLDER}/external/zlib/contrib/minizip/)
link_directories(${SHARED_MODULES}/http-request/build)
link_directories(${SRC_FOLDER}/external/flatbuffers/build/)

file(GLOB CONTENT_DOWNLOAD_SRC
    "src/*.cpp"
    )

add_library(content_manager SHARED
    ${CONTENT_DOWNLOAD_SRC}
    )

target_link_libraries(content_manager urlrequest gcc_s wazuhext lzma rocksdb flatbuffers)

set_target_properties(content_manager PROPERTIES
        BUILD_RPATH_USE_ORIGIN TRUE
        BUILD_RPATH "$ORIGIN/../lib"
)

add_subdirectory(testtool)
if(UNIT_TEST)
    add_subdirectory(tests)
endif()
