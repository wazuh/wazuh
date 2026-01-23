cmake_minimum_required(VERSION 3.12.4)

project(syscollector_test_tool)

include_directories(${CMAKE_SOURCE_DIR}/)
include_directories(${CMAKE_SOURCE_DIR}/testtool/)
include_directories(${SRC_FOLDER}/shared_modules/common/)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(${CMAKE_SOURCE_DIR}/src/)

link_directories(${CMAKE_BINARY_DIR}/lib)
link_directories(${SRC_FOLDER}/external/openssl/)
link_directories(${SRC_FOLDER}/external/procps/)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS
    "-g -Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -pthread"
)

file(GLOB SYSCOLLECTOR_TESTTOOL_SRC "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

add_executable(syscollector_test_tool ${SYSCOLLECTOR_TESTTOOL_SRC})

set_target_properties(
  syscollector_test_tool PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                    "${CMAKE_BINARY_DIR}/bin")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  target_link_libraries(
    syscollector_test_tool
    dbsync
    sysinfo
    syscollector
    psapi
    iphlpapi
    crypto
    ssl
    ws2_32
    crypt32
    -static-libstdc++)
elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  target_link_libraries(syscollector_test_tool dbsync sysinfo syscollector
                        pthread)
else()
  target_link_libraries(syscollector_test_tool dbsync sysinfo syscollector dl
                        proc)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
