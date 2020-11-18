cmake_minimum_required(VERSION 2.6.4)

project(syscollector)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

get_filename_component(SRC_FOLDER     ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)

if(COVERITY)
  add_definitions(-D__GNUC__=8)
endif(COVERITY)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -std=c++14")

set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(${SRC_FOLDER}/)
include_directories(${SRC_FOLDER}/headers/)
include_directories(${SRC_FOLDER}/external/sqlite/)
include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(${SRC_FOLDER}/external/cJSON/)
include_directories(${SRC_FOLDER}/external/procps/)
include_directories(${SRC_FOLDER}/external/bzip2/)
include_directories(${SRC_FOLDER}/external/openssl/include/)
include_directories(${SRC_FOLDER}/shared_modules/utils)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/rsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/common/)
include_directories(${SRC_FOLDER}/data_provider/include/)
include_directories(${CMAKE_SOURCE_DIR}/include)

link_directories(${SRC_FOLDER}/external/openssl/)
link_directories(${SRC_FOLDER}/external/sqlite/)
link_directories(${SRC_FOLDER}/external/cJSON/)
link_directories(${SRC_FOLDER}/external/procps/)
link_directories(${SRC_FOLDER}/external/bzip2/)
link_directories(${SRC_FOLDER}/shared_modules/dbsync/build/lib)
link_directories(${SRC_FOLDER}/shared_modules/rsync/build/lib)
link_directories(${SRC_FOLDER}/data_provider/build/lib)

link_directories(${SRC_FOLDER}/external/openssl/)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DWIN32=1
                  -D_WIN32_WINNT=0x600
                  -DWIN_EXPORT)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

file(GLOB SYSCOLLECTOR_SRC
    "${CMAKE_SOURCE_DIR}/src/*.cpp"
    )

add_library(syscollector SHARED 
    ${SYSCOLLECTOR_SRC}
    )

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set_target_properties(syscollector PROPERTIES
        PREFIX ""
        SUFFIX ".dll"
        LINK_FLAGS "-Wl,--add-stdcall-alias -static-libgcc -static-libstdc++"
        POSITION_INDEPENDENT_CODE 0 # this is to avoid MinGW warning;
        # MinGW generates position-independent-code for DLL by default
  )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set_target_properties(syscollector PROPERTIES
        LINK_FLAGS "-static-libgcc -static-libstdc++")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

target_link_libraries(syscollector crypto dbsync rsync sysinfo cjson pthread)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  target_link_libraries(syscollector crypto ws2_32 ssl crypt32 sqlite3 cjson gcov)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_link_libraries(syscollector -fprofile-arcs)
  else()
    target_link_libraries(syscollector gcov)
  endif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  if(UNIT_TEST)
    include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
    include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)
    link_directories(${SRC_FOLDER}/external/googletest/lib/)
  endif(UNIT_TEST)
else()
    add_subdirectory(testtool)
endif(CMAKE_BUILD_TYPE STREQUAL "Debug")

if(UNIT_TEST)
add_subdirectory(tests)
endif(UNIT_TEST)
