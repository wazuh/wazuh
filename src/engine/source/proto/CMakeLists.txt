set(ENGINE_EMESSAGES_INCLUDE_DIR ${ENGINE_SOURCE_DIR}/proto/include)
set(GENERATE_PROTOBUF_SCRIPT ${ENGINE_SOURCE_DIR}/proto/generateCode.sh)

# ###################################################################################################
# Dependencies
# ###################################################################################################
# Add google protobuf
CPMAddPackage(
  NAME protobuf
  GITHUB_REPOSITORY google/protobuf
  GIT_TAG v21.12
  VERSION 21.12
  EXCLUDE_FROM_ALL YES
  # Disable test
  OPTIONS "protobuf_BUILD_TESTS OFF"
  # Disable install
  OPTIONS "protobuf_BUILD_PROTOC_BINARIES OFF"
  OPTIONS "protobuf_BUILD_PROTOBUF_LITE OFF"
  OPTIONS "protobuf_BUILD_SHARED_LIBS OFF"
  OPTIONS "protobuf_BUILD_STATIC_LIBS ON"
  OPTIONS "protobuf_MSVC_STATIC_RUNTIME OFF"
  OPTIONS "protobuf_WITH_ZLIB OFF"
)

# ###################################################################################################
# Sources - Includes
# ###################################################################################################
file(GLOB EMESSAGE_AUTO_SOURCES "${ENGINE_EMESSAGES_INCLUDE_DIR}/eMessages/*.cc")

message(STATUS "${PROTO_FILES}")

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
    message(STATUS "Protobuf code generation is enabled")
    add_custom_target(generate_protobuf_code
        COMMAND /bin/sh ${GENERATE_PROTOBUF_SCRIPT}
    )
    add_dependencies(eMessages generate_protobuf_code)
else()
    message(STATUS "Protobuf code generation is disabled")
endif()
