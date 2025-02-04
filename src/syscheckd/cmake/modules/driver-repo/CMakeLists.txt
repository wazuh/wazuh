cmake_minimum_required(VERSION 3.5.1)

project(driver-repo NONE)

include(ExternalProject)
message(STATUS "Driver version: ${DRIVER_VERSION}")

ExternalProject_Add(
  driver
  URL "https://github.com/falcosecurity/libs/archive/${DRIVER_VERSION}.tar.gz"
  URL_HASH "${DRIVER_CHECKSUM}"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ""
  TEST_COMMAND ""
  PATCH_COMMAND sh -c "mv ./driver ../driver.tmp && rm -rf ./* && mv ../driver.tmp/* ."
)
