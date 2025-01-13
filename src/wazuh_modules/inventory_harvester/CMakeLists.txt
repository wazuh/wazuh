cmake_minimum_required(VERSION 3.12.4)

project(inventory_harvester)

enable_testing()

add_definitions(-DPROMISE_TYPE=PromiseType::NORMAL)

# If VERSION and REVISION are manually set, use them.
if (VERSION AND REVISION)
    add_definitions(-DVERSION="${VERSION}")
    add_definitions(-DREVISION="${REVISION}")
endif ()

# Include directories
include_directories(include)

file(GLOB INVENTORY_HARVESTER_SRC
    "src/*.cpp"
    )

add_library(inventory_harvester SHARED
    ${INVENTORY_HARVESTER_SRC}
    )

#add_dependencies(inventory_harvester compile_schemas) #Add a dependency between top-level targets.

#target_link_libraries(inventory_harvester indexer_connector router gcc_s flatbuffers)

set_target_properties(inventory_harvester PROPERTIES
        BUILD_RPATH_USE_ORIGIN TRUE
        BUILD_RPATH "$ORIGIN/../lib"
)
