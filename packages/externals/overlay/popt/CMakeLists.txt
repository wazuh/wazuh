cmake_minimum_required(VERSION 3.12.4)

include(ExternalProject)

project(popt)

set(POPT_SRC ${CMAKE_CURRENT_SOURCE_DIR}/)
set(POPT_OUT ${CMAKE_CURRENT_BINARY_DIR}/output)
set(POPT_PUBLIC_INCLUDES ${POPT_OUT}/include)
set(POPT_STATIC_LIB ${POPT_OUT}/src/.libs/libpopt.a)

file(MAKE_DIRECTORY ${POPT_PUBLIC_INCLUDES})

ExternalProject_Add(
  upstream_popt
  SOURCE_DIR ${POPT_SRC}
  BINARY_DIR ${POPT_OUT}
  CONFIGURE_COMMAND ${POPT_SRC}/configure --disable-scripts --disable-doc --enable-static --disable-shared CFLAGS=-fPIC
  BUILD_ALWAYS 1
  INSTALL_COMMAND ""
  BUILD_BYPRODUCTS ${POPT_STATIC_LIB}
)

configure_file(${POPT_SRC}/src/popt.h ${POPT_PUBLIC_INCLUDES} COPYONLY)

add_library(popt STATIC IMPORTED GLOBAL)

add_dependencies(popt upstream_popt)

set_target_properties(popt PROPERTIES IMPORTED_LOCATION ${POPT_STATIC_LIB})
set_target_properties(popt PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${POPT_PUBLIC_INCLUDES})
