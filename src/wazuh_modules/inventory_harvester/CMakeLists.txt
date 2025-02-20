cmake_minimum_required(VERSION 3.12.4)

project(inventory_harvester)

enable_testing()

add_definitions(-DPROMISE_TYPE=PromiseType::NORMAL)

include_directories(${SRC_FOLDER}/external/flatbuffers/include)

# If VERSION and REVISION are manually set, use them.
if (VERSION AND REVISION)
    add_definitions(-DVERSION="${VERSION}")
    add_definitions(-DREVISION="${REVISION}")
endif ()

# Include directories
include_directories(include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/wcsModel)

file(GLOB INVENTORY_HARVESTER_SRC
    "src/*.cpp"
    )

add_library(inventory_harvester SHARED
    ${INVENTORY_HARVESTER_SRC}
    )

target_link_libraries(inventory_harvester indexer_connector router gcc_s flatbuffers)

set_target_properties(inventory_harvester PROPERTIES
        BUILD_RPATH_USE_ORIGIN TRUE
        BUILD_RPATH "$ORIGIN/../lib"
)

add_dependencies(inventory_harvester compile_schemas_input)

add_subdirectory(testtool)

if(UNIT_TEST)
  add_subdirectory(tests)
else()
  if(FSANITIZE)
    set(CMAKE_CXX_FLAGS_DEBUG "-g -fsanitize=address,leak,undefined")
  endif(FSANITIZE)
endif(UNIT_TEST)
