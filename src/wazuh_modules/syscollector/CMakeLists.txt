project(syscollector)

include_directories(${CMAKE_SOURCE_DIR}/wazuh_modules/syscollector/include)
include_directories(${CMAKE_SOURCE_DIR}/data_provider/include)
include_directories(${CMAKE_SOURCE_DIR}/shared_modules/dbsync/include)
include_directories(${CMAKE_SOURCE_DIR}/shared_modules/rsync/include)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DWIN32=1
                  -D_WIN32_WINNT=0x600
                  -DWIN_EXPORT)
endif()

file(GLOB SYSCOLLECTOR_SRC
    "${CMAKE_SOURCE_DIR}/wazuh_modules/syscollector/src/*.cpp"
    )

add_library(syscollector SHARED
    ${SYSCOLLECTOR_SRC}
    )

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set_target_properties(syscollector PROPERTIES
        PREFIX ""
        SUFFIX ".dll"
        LINK_FLAGS "-Wl,--add-stdcall-alias"
        POSITION_INDEPENDENT_CODE 0 # this is to avoid MinGW warning;
        # MinGW generates position-independent-code for DLL by default
  )
elseif(UNIX AND NOT APPLE)
  if(NOT CMAKE_SYSTEM_NAME STREQUAL "AIX")
    string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,-rpath=$ORIGIN")
  endif()
endif()

if(NOT CMAKE_SYSTEM_NAME STREQUAL "AIX")
  target_link_libraries(syscollector dbsync rsync sysinfo wazuhext)
else()
  string(REPLACE ";" ":" CXX_IMPLICIT_LINK_DIRECTORIES_STR "${CMAKE_CXX_IMPLICIT_LINK_DIRECTORIES}")
  string(REPLACE ";" ":" PLATFORM_REQUIRED_RUNTIME_PATH_STR "${CMAKE_PLATFORM_REQUIRED_RUNTIME_PATH}")
  target_link_libraries(syscollector dbsync rsync sysinfo wazuhext -Wl,-blibpath:${INSTALL_PREFIX}/lib:${CXX_IMPLICIT_LINK_DIRECTORIES_STR}:${PLATFORM_REQUIRED_RUNTIME_PATH_STR})
endif()

if(UNIT_TESTS)
  add_subdirectory(tests)
endif(UNIT_TESTS)

add_subdirectory(testtool)
