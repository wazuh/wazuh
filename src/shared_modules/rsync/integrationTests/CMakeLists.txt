cmake_minimum_required(VERSION 3.12.4)

project(integration_tests)

include_directories(${EXTERNAL_LIB}/googletest/googletest/include/)
include_directories(${EXTERNAL_LIB}/googletest/googlemock/include/)
include_directories(${CMAKE_SOURCE_DIR}/src/)
link_directories(${EXTERNAL_LIB}/googletest/lib/)
