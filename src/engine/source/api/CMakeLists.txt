set(ENGINE_API_SOURCE_DIR ${ENGINE_SOURCE_DIR}/api/src)
set(ENGINE_API_INCLUDE_DIR ${ENGINE_SOURCE_DIR}/api/include)

# ###################################################################################################
# Dependencies
# ###################################################################################################
# yaml-cpp::yaml-cpp vs yaml-cpp #FIXME 70 stars on github
CPMAddPackage(
    NAME yaml-cpp
    GITHUB_REPOSITORY jbeder/yaml-cpp
    GIT_TAG yaml-cpp-0.7.0
    VERSION 0.7.0
    OPTIONS
    "YAML_BUILD_SHARED_LIBS OFF"
    "YAML_CPP_BUILD_TESTS OFF"
    EXCLUDE_FROM_ALL YES
)

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
add_library(api STATIC
    ${ENGINE_API_SOURCE_DIR}/registry.cpp
    ${ENGINE_API_SOURCE_DIR}/catalog/catalog.cpp
    ${ENGINE_API_SOURCE_DIR}/catalog/commands.cpp
    ${ENGINE_API_SOURCE_DIR}/kvdb/commands.cpp
)

target_include_directories(api
    PUBLIC
    ${ENGINE_API_INCLUDE_DIR}
    PRIVATE
    ${ENGINE_API_SOURCE_DIR}
    ${ENGINE_API_SOURCE_DIR}/catalog
    ${ENGINE_API_SOURCE_DIR}/kvdb
    ${ENGINE_API_SOURCE_DIR}/router
    # TODO: Move msg to a separate library
    ${ENGINE_API_SOURCE_DIR}/messages
)

# TODO Move protobuf to a separate library with the messages
target_link_libraries(api base json builder::ivalidator store::istore yaml-cpp fmt kvdb router protobuf::libprotobuf)
