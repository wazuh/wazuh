project(database_feed)

enable_testing()

list(APPEND Schemas
            cve5
            vulnerabilityCandidate
            vulnerabilityDescription
            vulnerabilityRemediations
            packageTranslation
)

find_program(FLATC flatc)
if(NOT FLATC)
    message(FATAL_ERROR "flatc not found")
endif()

add_custom_target(compile_schemas)
foreach(schema IN LISTS Schemas)
  set(FILE "./schemas/${schema}.fbs")
  set(VULNERABILITY_OUTPUT_HEADER_GENERATED "${CMAKE_CURRENT_SOURCE_DIR}/include/${schema}_generated.h")
  set(VULNERABILITY_OUTPUT_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/include/${schema}_schema.h")

  add_custom_command(
      OUTPUT "${VULNERABILITY_OUTPUT_HEADER_GENERATED}"
      COMMAND ${FLATC}
      ARGS --cpp
      ARGS -o "${CMAKE_CURRENT_SOURCE_DIR}/include" "${FILE}"
      ARGS --no-warnings
      COMMENT "Building C++ header for ${schema} schema."
      DEPENDS ${FILE}
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

  add_custom_command(
      OUTPUT "${VULNERABILITY_OUTPUT_HEADER}"
      COMMAND bash -c "echo -e '// This file was generated from ${FILE} , do not modify \\n#ifndef ${schema}_HEADER\\n#define ${schema}_HEADER\\nauto constexpr ${schema}_SCHEMA = R\"('`cat ${FILE}`')\" ;\\n#endif // ${schema}_HEADER\\n ' > ./include/${schema}_schema.h"
      COMMENT "Creating header from schema file: '${schema}'"
      DEPENDS ${VULNERABILITY_OUTPUT_HEADER_GENERATED}
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      VERBATIM)

  add_custom_target(${schema}_schema_target DEPENDS ${VULNERABILITY_OUTPUT_HEADER})
  add_dependencies(compile_schemas ${schema}_schema_target)
endforeach()

file(GLOB DATABASE_FEED_SRC
    "src/*.cpp"
    )

# Add fpic flag
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(database_feed STATIC
    ${DATABASE_FEED_SRC}
    )

target_include_directories(database_feed PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_dependencies(database_feed compile_schemas)

target_link_libraries(database_feed
        PUBLIC
        base
        PRIVATE
        flatbuffers::flatbuffers
        RocksDB::rocksdb
        filesystem
        )


# Tests
if(ENGINE_BUILD_TEST)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)

add_library(feedmanager_mocks INTERFACE)
target_include_directories(feedmanager_mocks INTERFACE ${TEST_MOCK_DIR})
add_library(feedmanager::mocks ALIAS feedmanager_mocks)
endif(ENGINE_BUILD_TEST)