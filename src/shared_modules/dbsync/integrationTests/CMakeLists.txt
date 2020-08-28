cmake_minimum_required(VERSION 3.12)

project(integration_tests)

include_directories(${EXTERNAL_LIBS_PATH}/googletest/googletest/include/)
include_directories(${EXTERNAL_LIBS_PATH}/googletest/googlemock/include/)
include_directories(${CMAKE_SOURCE_DIR}/include/)

link_directories(${CMAKE_BINARY_DIR}/lib
				 ${EXTERNAL_LIBS_PATH}/googletest/lib/)

add_subdirectory(fim)
