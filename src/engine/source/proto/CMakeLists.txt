set(ENGINE_EMESSAGES_INCLUDE_DIR ${ENGINE_SOURCE_DIR}/proto/include)
set(GENERATE_PROTOBUF_SCRIPT ${ENGINE_SOURCE_DIR}/proto/generateCode.sh)

# ###################################################################################################
# Sources - Includes
# ###################################################################################################
file(GLOB EMESSAGE_AUTO_SOURCES "${ENGINE_EMESSAGES_INCLUDE_DIR}/eMessages/*.cc")

add_library(eMessages STATIC)

target_sources(eMessages
    PRIVATE
    ${EMESSAGE_AUTO_SOURCES}
)

target_include_directories(eMessages
    PUBLIC
    ${ENGINE_EMESSAGES_INCLUDE_DIR}
)

target_link_libraries(eMessages PUBLIC protobuf::libprotobuf base)

# ###################################################################################################
# Add custom target for code generation trigger
# ###################################################################################################
find_program(PROTOC_EXECUTABLE NAMES protoc)

# Execute only if protoc is found and ENGINE_GENERATE_PROTO is ON
if(PROTOC_EXECUTABLE)
    message(STATUS "Found protoc: ${PROTOC_EXECUTABLE}")
    set(VCPKG_INSTALLED_DIR ${CMAKE_BINARY_DIR}/vcpkg_installed/${VCPKG_TARGET_TRIPLET})

    # Check if ENGINE_GENERATE_PROTO is ON
    if(NOT ENGINE_GENERATE_PROTO)
        message(INFO "ENGINE_GENERATE_PROTO is OFF. Skipping Protobuf generation.")
        return()
    endif()
    add_custom_target(generate_protobuf_code
        COMMAND VCPKG_INSTALLED_DIR=${VCPKG_INSTALLED_DIR} /bin/sh ${GENERATE_PROTOBUF_SCRIPT}
    )
else()
    message(WARNING "protoc not found. Skipping Protobuf generation.")
endif()


if(TARGET generate_protobuf_code)
    add_dependencies(eMessages generate_protobuf_code)
endif()
