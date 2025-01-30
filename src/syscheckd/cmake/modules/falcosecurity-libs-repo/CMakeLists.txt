cmake_minimum_required(VERSION 3.5.1)

project(falcosecurity-libs-repo NONE)

include(ExternalProject)
message(STATUS "Libs version: ${FALCOSECURITY_LIBS_VERSION}")

ExternalProject_Add(
  falcosecurity-libs
  URL "https://github.com/falcosecurity/libs/archive/${FALCOSECURITY_LIBS_VERSION}.tar.gz"
  URL_HASH "${FALCOSECURITY_LIBS_CHECKSUM}"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ""
  TEST_COMMAND ""
  PATCH_COMMAND ""
)
