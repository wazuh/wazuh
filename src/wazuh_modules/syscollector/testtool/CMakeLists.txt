cmake_minimum_required(VERSION 2.6.4)

project(syscollector_test_tool)

include_directories(${CMAKE_SOURCE_DIR}/)
include_directories(${CMAKE_SOURCE_DIR}/testtool/)
include_directories(${SRC_FOLDER}/shared_modules/common/)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/rsync/include/)
include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(${CMAKE_SOURCE_DIR}/src/)

link_directories(${SRC_FOLDER}/shared_modules/dbsync/build/lib)
link_directories(${SRC_FOLDER}/shared_modules/rsync/build/lib)
link_directories(${SRC_FOLDER}/data_provider/build/lib)

if(COVERITY)
  add_definitions(-D__GNUC__=8)
endif(COVERITY)

set(CMAKE_CXX_FLAGS "-g -Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -std=c++14")

file(GLOB SYSCOLLECTOR_TESTTOOL_SRC
        "${CMAKE_SOURCE_DIR}/testtool/*.cpp"
        )
    
add_executable(syscollector_test_tool
               ${SYSCOLLECTOR_TESTTOOL_SRC}
               )

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(syscollector_test_tool
        rsync
        dbsync
        sysinfo
        syscollector
        psapi
        iphlpapi
        ws2_32
        -static-libgcc -static-libstdc++
    )
elseif (CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
    target_link_libraries(syscollector_test_tool
        rsync
        dbsync
        sysinfo
        syscollector
        pthread)
else()
    target_link_libraries(syscollector_test_tool
        rsync
        dbsync
        sysinfo
        syscollector
        dl
        pthread
        proc
    )

    if(SOLARIS)
        target_link_libraries(syscollector_test_tool
            nsl
            socket
        )
    endif(SOLARIS)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
