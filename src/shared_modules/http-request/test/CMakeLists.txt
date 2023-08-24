cmake_minimum_required(VERSION 3.12.4)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)
include_directories(${SRC_FOLDER}/external/cpp-httplib/)

add_subdirectory(benchmark)
add_subdirectory(component)
add_subdirectory(unit)
