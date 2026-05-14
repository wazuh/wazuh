cmake_minimum_required(VERSION 3.12.4)

project(unit_tests)

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_SOURCE_DIR}/include/)
include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)
include_directories(${SRC_FOLDER}/external/flatbuffers/include/)
link_directories(${SRC_FOLDER}/external/googletest/lib/)

add_subdirectory(sysCollectorImp)
add_subdirectory(sysNormalizer)

# TODO MOVE THIS TESTS to shared_modulesd/utils
# if (NOT ${TARGET} STREQUAL "")
#     if(${TARGET} STREQUAL "server")
#         add_subdirectory(sysCollectorFlatbuffers)
#     endif()
# endif()
