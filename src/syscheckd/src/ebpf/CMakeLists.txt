cmake_minimum_required(VERSION 3.12.4)

project(fimebpf)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  include_directories(${SRC_FOLDER}/syscheckd/src/ebpf/src/)
  include_directories(${SRC_FOLDER}/syscheckd/src/ebpf/include/)
  include_directories(${SRC_FOLDER}/external/falcolibs/)
  include_directories(${SRC_FOLDER}/external/falcolibs/userspace/)
  include_directories(${SRC_FOLDER}/external/falcolibs/build/)

  add_library(fimebpf SHARED ${CMAKE_SOURCE_DIR}/src/ebpf/src/ebpf_whodata.cpp)
  link_directories(${SRC_FOLDER}/external/falcolibs/build/libsinsp/)
  link_directories(${SRC_FOLDER}/external/falcolibs/build/libscap/)
  find_library(SINSP_LIBRARY sinsp HINTS ${SRC_FOLDER}/external/falcolibs/build/libsinsp)
  find_library(SCAP_LIBRARY scap HINTS ${SRC_FOLDER}/external/falcolibs/build/libscap)
  target_link_libraries(fimebpf ${SINSP_LIBRARY} ${SCAP_LIBRARY})
endif()
