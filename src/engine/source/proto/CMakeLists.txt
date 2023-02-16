set(ENGINE_EMESSAGES_INCLUDE_DIR ${ENGINE_SOURCE_DIR}/proto/include)

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
file(GLOB EMESSAGE_AUTO_HEADERS "${ENGINE_EMESSAGES_INCLUDE_DIR}/eMessages/*.h")

add_library(eMessages STATIC ${EMESSAGE_AUTO_SOURCES})

target_sources(eMessages
    PUBLIC
    ${EMESSAGE_HEADERS}
    PRIVATE
    ${EMESSAGE_SOURCES}
)

target_include_directories(eMessages
    PUBLIC
    ${ENGINE_EMESSAGES_INCLUDE_DIR}
)

target_link_libraries(eMessages PUBLIC protobuf::libprotobuf base)
