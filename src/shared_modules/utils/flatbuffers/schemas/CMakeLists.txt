get_filename_component(FLATC_PATH ${CMAKE_SOURCE_DIR}/external/flatbuffers/build/ ABSOLUTE)

list(APPEND schemas
            syscollector_deltas
            syscheck_deltas
            rsync
            messageBuffer
)

add_custom_target(compile_schemas_input)
foreach(schema IN LISTS schemas)
    message("Building ${schema} schema")
    message("${CMAKE_SOURCE_DIR}")
    message("${CMAKE_CURRENT_SOURCE_DIR}")
    set(FBS_FILE "${CMAKE_SOURCE_DIR}/shared_modules/utils/flatbuffers/schemas/${schema}.fbs")
    set(OUTPUT_HEADER_GENERATED "${CMAKE_SOURCE_DIR}/shared_modules/utils/flatbuffers/include/${schema}_generated.h")
    set(OUTPUT_HEADER "${CMAKE_SOURCE_DIR}/shared_modules/utils/flatbuffers/include/${schema}_schema.h")

    add_custom_command(
    OUTPUT "${OUTPUT_HEADER_GENERATED}"
    COMMAND ${FLATC_PATH}/flatc
    ARGS -c
    ARGS -o "${CMAKE_SOURCE_DIR}/shared_modules/utils/flatbuffers/include" "${FBS_FILE}"
    ARGS --no-warnings
    COMMENT "Executing flatc to generate ${schema} header file."
    )

    add_custom_command(
        OUTPUT "${OUTPUT_HEADER}"
        COMMAND bash -c "echo -e '// This file was generated from ${FBS_FILE} , do not modify \\n#ifndef ${schema}_HEADER\\n#define ${schema}_HEADER\\n#define ${schema}_SCHEMA \"'`cat ${FBS_FILE}`'\" \\n#endif // ${schema}_HEADER\\n ' > ${CMAKE_SOURCE_DIR}/shared_modules/utils/flatbuffers/include/${schema}_schema.h"
        COMMENT "Creating header from schema file: '${schema}'"
        DEPENDS "${OUTPUT_HEADER_GENERATED}"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        VERBATIM)

    add_custom_target(${schema}_schema_input_target DEPENDS ${OUTPUT_HEADER})
    add_dependencies(compile_schemas_input ${schema}_schema_input_target)
endforeach()
