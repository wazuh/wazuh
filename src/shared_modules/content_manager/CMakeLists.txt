cmake_minimum_required(VERSION 3.12.4)

project(content_manager)

enable_testing()

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
include_directories(${SRC_FOLDER}/external/nlohmann)
include_directories(${SRC_FOLDER}/external/curl/include/curl)

include_directories(${SHARED_MODULES})
include_directories(${SHARED_MODULES}/utils)
include_directories(${SHARED_MODULES}/router/include)
include_directories(${SHARED_MODULES}/http-request/include)
include_directories(${SHARED_MODULES}/content_manager/src/components)

# Link directories
link_directories(${SRC_FOLDER}/external/curl/lib/.libs)
link_directories(${SHARED_MODULES}/router/build)
link_directories(${SHARED_MODULES}/http-request/build)

file(GLOB CONTENT_DOWNLOAD_SRC
    "src/*.cpp"
    )

add_library(content_manager SHARED
    ${CONTENT_DOWNLOAD_SRC}
    )

target_link_libraries(content_manager router urlrequest gcc_s curl)

set_target_properties(content_manager PROPERTIES
        BUILD_RPATH_USE_ORIGIN TRUE
        BUILD_RPATH "$ORIGIN/../lib"
)

add_subdirectory(testtool)
add_subdirectory(tests)
