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


include_directories(${SRC_FOLDER}/external/sqlite/)
include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(${SRC_FOLDER}/external/cJSON/)
include_directories(${SRC_FOLDER}/headers/)
include_directories(${SRC_FOLDER}/shared_modules/utils)
include_directories(${CMAKE_SOURCE_DIR}/)

link_directories(${SRC_FOLDER}/external/sqlite/)
link_directories(${SRC_FOLDER}/external/cJSON/)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  file(GLOB SYSCOLLECTOR_SRC
      "${CMAKE_SOURCE_DIR}/*Win.cpp")
  add_definitions(-DWIN32=1)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  file(GLOB SYSCOLLECTOR_SRC
      "${CMAKE_SOURCE_DIR}/*Linux.cpp")
else()
  if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    file(GLOB SYSCOLLECTOR_SRC
        "${CMAKE_SOURCE_DIR}/*Mac.cpp"
        "${CMAKE_SOURCE_DIR}/*CommonBSD.cpp")
  elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    file(GLOB SYSCOLLECTOR_SRC
        "${CMAKE_SOURCE_DIR}/*FreeBSD.cpp"
        "${CMAKE_SOURCE_DIR}/*CommonBSD.cpp")
  elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
    file(GLOB SYSCOLLECTOR_SRC
        "${CMAKE_SOURCE_DIR}/*OpenBSD.cpp"
        "${CMAKE_SOURCE_DIR}/*CommonBSD.cpp")
  endif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")


add_library(syscollector OBJECT 
    "${SYSCOLLECTOR_SRC}"
    "${CMAKE_SOURCE_DIR}/syscollectorImp.cpp"
    "${CMAKE_SOURCE_DIR}/sysInfo.cpp" )

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_link_libraries(syscollector sqlite3 cjson gcov)
  if(UNIT_TEST)
    include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
    include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)
    link_directories(${SRC_FOLDER}/external/googletest/lib/)
  endif(UNIT_TEST)
else()
    target_link_libraries(syscollector sqlite3 cjson)
endif(CMAKE_BUILD_TYPE STREQUAL "Debug")

 add_custom_target(copy-files ALL
    COMMAND ${CMAKE_COMMAND} -E copy
    ${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/syscollector.dir/*.o*
    ${CMAKE_SOURCE_DIR}/
    DEPENDS syscollector
    )

add_subdirectory(testtool)
if(UNIT_TEST)
add_subdirectory(tests)
endif(UNIT_TEST)
