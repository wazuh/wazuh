cmake_minimum_required(VERSION 3.12.4)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)
include_directories(${SRC_FOLDER}/shared_modules/content_manager/src/)
include_directories(${SRC_FOLDER}/shared_modules/content_manager/include/)

link_directories(${SRC_FOLDER}/external/googletest/lib/)

add_subdirectory(component)
add_subdirectory(unit)
