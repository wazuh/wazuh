cmake_minimum_required(VERSION 3.12.4)

if(FSANITIZE)
set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage -fsanitize=address,leak,undefined")
endif()

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)
include_directories(${SRC_FOLDER}/shared_modules/keystore/)

link_directories(${SRC_FOLDER}/external/googletest/lib/)

add_subdirectory(component)
