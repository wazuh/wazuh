project(unit_tests)

set(CMAKE_CXX_FLAGS "-Wall -Wextra --coverage")

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  string(APPEND CMAKE_EXE_LINKER_FLAGS " -fprofile-arcs ")
else()
  string(APPEND CMAKE_EXE_LINKER_FLAGS " -lgcov ")
endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

add_subdirectory(sqlite)
add_subdirectory(interface)
add_subdirectory(pipelineFactory)
add_subdirectory(dbengine)
