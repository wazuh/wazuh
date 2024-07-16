cmake_minimum_required(VERSION 3.12.4)

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
link_directories(${SRC_FOLDER}/external/openssl/)
link_directories(${SRC_FOLDER}/external/procps/)

if(COVERITY)
  add_definitions(-D__GNUC__=8)
endif(COVERITY)
add_definitions(-DWAZUH_UNIT_TESTING)

set(CMAKE_CXX_FLAGS "-g -Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -std=c++14 -pthread")

if(FSANITIZE)
  set(CMAKE_CXX_FLAGS_DEBUG "-fsanitize=address,leak,undefined")
endif(FSANITIZE)

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
        crypto
        ssl
        ws2_32
        crypt32
        -static-libstdc++
    )
elseif (CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
    target_link_libraries(syscollector_test_tool
        rsync
        dbsync
        sysinfo
        syscollector
        pthread)
elseif (CMAKE_SYSTEM_NAME STREQUAL "AIX")
    target_link_libraries(syscollector_test_tool
        rsync
        dbsync
        sysinfo
        syscollector
        dl)
else()
    target_link_libraries(syscollector_test_tool
        rsync
        dbsync
        sysinfo
        syscollector
        dl
        proc
    )

    if(SOLARIS)
        target_link_libraries(syscollector_test_tool
            nsl
            socket
        )
    endif(SOLARIS)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
