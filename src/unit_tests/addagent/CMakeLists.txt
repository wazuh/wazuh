# Generate addagent library
# Temporay fix because it will be deleted by https://github.com/wazuh/wazuh/issues/30924
# Define the required addagent object files explicitly
set(REQUIRED_ADDAGENT_OBJECTS
    ${SRC_FOLDER}/addagent/manage_agents.o
    ${SRC_FOLDER}/addagent/manage_keys.o
    ${SRC_FOLDER}/addagent/read_from_user.o
    ${SRC_FOLDER}/addagent/validate.o
)

# Add custom target to build addagent object files using make
add_custom_target(build_addagent_objects
    COMMAND ${CMAKE_MAKE_PROGRAM} TARGET=${TARGET} addagent/manage_agents.o addagent/manage_keys.o addagent/read_from_user.o addagent/validate.o
    WORKING_DIRECTORY ${SRC_FOLDER}
    COMMENT "Building addagent object files"
)

add_library(ADDAGENT_O STATIC ${REQUIRED_ADDAGENT_OBJECTS})

# Make ADDAGENT_O depend on building the object files first
add_dependencies(ADDAGENT_O build_addagent_objects)

set_source_files_properties(
    ${REQUIRED_ADDAGENT_OBJECTS}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    ADDAGENT_O
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(ADDAGENT_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

list(APPEND addagent_names "test_manage_keys")
list(APPEND addagent_flags "${DEBUG_OP_WRAPPERS} ${STDIO_OP_WRAPPERS} \
                            -Wl,--wrap,mkstemp_ex \
                            -Wl,--wrap,stat -Wl,--wrap,chmod -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,fprintf -Wl,--wrap,fgets -Wl,--wrap,rename_ex\
                            -Wl,--wrap,encode_base64 -Wl,--wrap,decode_base64 -Wl,--wrap,wfopen -Wl,--wrap,popen")

list(LENGTH addagent_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET addagent_names ${counter} addagent_test_name)
    list(GET addagent_flags ${counter} addagent_test_flags)

    add_executable(${addagent_test_name} ${addagent_test_name}.c)

    target_link_libraries(
        ${addagent_test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        ADDAGENT_O
        ${TEST_DEPS}
    )
    if(NOT addagent_test_flags STREQUAL " ")
        target_link_libraries(
            ${addagent_test_name}
            ${addagent_test_flags}
        )
    endif()
    add_test(NAME ${addagent_test_name} COMMAND ${addagent_test_name})
endforeach()
