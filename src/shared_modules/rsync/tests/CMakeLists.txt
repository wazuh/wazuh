project(unit_tests)

set(CMAKE_CXX_FLAGS "--coverage")

include_directories(${SRC_FOLDER}/shared_modules/dbsync/src/)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  string(APPEND CMAKE_EXE_LINKER_FLAGS " -fprofile-arcs ")
else()
  string(APPEND CMAKE_EXE_LINKER_FLAGS " -lgcov ")
endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

add_subdirectory(interface)
add_subdirectory(implementation)
