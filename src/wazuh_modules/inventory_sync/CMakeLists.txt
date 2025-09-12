cmake_minimum_required(VERSION 3.12.4)

project(inventory_sync)

enable_testing()

add_definitions(-DPROMISE_TYPE=PromiseType::NORMAL)

include_directories(${SRC_FOLDER})

# If VERSION and REVISION are manually set, use them.
if (VERSION AND REVISION)
    add_definitions(-DVERSION="${VERSION}")
    add_definitions(-DREVISION="${REVISION}")
endif ()

# Include directories
include_directories(include)
include_directories(${SRC_FOLDER}/external/flatbuffers/include)

file(GLOB INVENTORY_SYNC_SRC
    "src/*.cpp"
    )

add_library(inventory_sync SHARED
    ${INVENTORY_SYNC_SRC}
    )

target_link_libraries(inventory_sync indexer_connector router gcc_s flatbuffers)

set_target_properties(inventory_sync PROPERTIES
        BUILD_RPATH_USE_ORIGIN TRUE
        BUILD_RPATH "$ORIGIN/../lib"
)

if (TARGET compile_schemas_input)
    # If target isn't defined, only this project is being built and not the whole Wazuh project.
    # The schemas must be compiled manually before building this project in that case.
    add_dependencies(inventory_sync compile_schemas_input)
endif()

if(UNIT_TEST)
add_subdirectory(tests)
endif()
add_subdirectory(testtool)
