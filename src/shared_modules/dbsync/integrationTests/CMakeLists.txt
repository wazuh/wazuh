project(integration_tests)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  string(APPEND CMAKE_EXE_LINKER_FLAGS " -fprofile-arcs ")
else()
  string(APPEND CMAKE_EXE_LINKER_FLAGS " -lgcov ")
endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

add_subdirectory(fim)
