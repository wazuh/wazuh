# Build type and compiler flags of the external dependencies built from sources.
#
# In: CMAKE_BUILD_TYPE, IS_WINDOWS, FSANITIZE, TSANITIZE, EXTERNAL_SANITIZE.
# Out: DEPS_BUILD_TYPE, DEPS_CFLAGS_LIST, DEPS_CMAKE_ARGS, DEPS_CFLAGS_ENV, DEPS_CFLAGS_EXTRA.
#
# Only the build from sources inherits them. They stay empty (and the recipes
# expand exactly as without them) unless the project builds Debug, so the
# precompiled artifacts of the pool are always Release and uninstrumented.
# The sanitizers need EXTERNAL_SANITIZE as well: the project instruments only
# its C++, and its C executables link libwazuhext, which holds the
# dependencies, without a sanitizer runtime.

set(DEPS_BUILD_TYPE Release)
set(DEPS_CFLAGS_LIST "")
string(TOUPPER "${CMAKE_BUILD_TYPE}" _deps_project_build_type)
if(_deps_project_build_type STREQUAL "DEBUG" AND NOT IS_WINDOWS)
  set(DEPS_BUILD_TYPE Debug)
  # Last on the command line, so it beats the -O2 that some recipes (bzip2, lua) set themselves.
  set(DEPS_CFLAGS_LIST -g -O0)
  if(EXTERNAL_SANITIZE AND FSANITIZE)
    list(APPEND DEPS_CFLAGS_LIST -fsanitize=address,leak,undefined)
  elseif(EXTERNAL_SANITIZE AND TSANITIZE)
    list(APPEND DEPS_CFLAGS_LIST -fsanitize=thread)
  endif()
endif()
set(DEPS_CMAKE_ARGS -DCMAKE_BUILD_TYPE=${DEPS_BUILD_TYPE})
set(DEPS_CFLAGS_ENV "")
set(DEPS_CFLAGS_EXTRA "")
if(DEPS_CFLAGS_LIST)
  string(JOIN " " DEPS_CFLAGS_JOINED ${DEPS_CFLAGS_LIST})
  list(APPEND DEPS_CMAKE_ARGS "-DCMAKE_C_FLAGS=${DEPS_CFLAGS_JOINED}"
       "-DCMAKE_CXX_FLAGS=${DEPS_CFLAGS_JOINED}")
  set(DEPS_CFLAGS_ENV "CFLAGS=${DEPS_CFLAGS_JOINED}")
  set(DEPS_CFLAGS_EXTRA " ${DEPS_CFLAGS_JOINED}")
endif()
