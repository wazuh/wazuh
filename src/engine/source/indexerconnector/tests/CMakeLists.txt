cmake_minimum_required(VERSION 3.12.4)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage -fsanitize=address,leak,undefined")

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)
include_directories(${SRC_FOLDER}/shared_modules/indexer_connector/include/)
include_directories(${SRC_FOLDER}/shared_modules/indexer_connector/src/)

link_directories(${SRC_FOLDER}/external/googletest/lib/)

add_subdirectory(unit)
add_subdirectory(component)
