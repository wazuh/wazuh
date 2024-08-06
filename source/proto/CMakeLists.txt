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
if(ENGINE_GENERATE_PROTOBUF)
    message(STATUS "Regenerate Protobuf code")
    add_custom_target(generate_protobuf_code
        COMMAND /bin/sh ${GENERATE_PROTOBUF_SCRIPT}
    )
    add_dependencies(eMessages generate_protobuf_code)
endif()
