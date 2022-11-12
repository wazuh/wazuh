project(unit_tests)

set(CMAKE_CXX_FLAGS_DEBUG "--coverage")

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)
link_directories(${SRC_FOLDER}/external/googletest/lib/)

add_subdirectory(sysCollectorImp)
add_subdirectory(sysNormalizer)

