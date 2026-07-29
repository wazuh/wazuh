# Links jemalloc onto a server-only daemon target, explicitly and per-target.
#
# jemalloc is only built for server (non-agent, non-Windows) targets — see
# the jemalloc section in external/CMakeLists.txt — and can be turned off
# entirely with -DDISABLE_JEMALLOC=ON.
#
# Each daemon that wants jemalloc's allocator must call this itself. It is
# intentionally NOT linked onto any shared static library (e.g. `config` or
# `wazuh_modulesd_lib`): a static library can't hide a dependency from its
# consumers, so linking jemalloc there would silently drag it into every
# daemon that happens to link that library, whether or not it actually
# wants it. This function makes the choice visible at each call site instead.
#
# Usage: wazuh_link_jemalloc(<target> [PLAIN])
#   PLAIN: use the plain (non-keyword) target_link_libraries() signature.
#   CMake forbids mixing plain and keyword calls on the same target, so pass
#   PLAIN for a target (e.g. wazuh-engine) that already links itself with
#   the plain signature elsewhere. Defaults to the keyword PRIVATE signature.

function(wazuh_link_jemalloc target)
  if(IS_AGENT OR CMAKE_SYSTEM_NAME STREQUAL "Windows")
    return()
  endif()

  if(DEFINED DISABLE_JEMALLOC AND DISABLE_JEMALLOC)
    return()
  endif()

  find_library(
    JEMALLOC_LIB jemalloc
    PATHS ${CMAKE_SOURCE_DIR}/external/jemalloc/lib
    NO_DEFAULT_PATH)

  if(NOT JEMALLOC_LIB)
    message(WARNING "jemalloc not found in ${CMAKE_SOURCE_DIR}/external/jemalloc/lib, ${target} will use the default allocator")
    return()
  endif()

  if("${ARGV1}" STREQUAL "PLAIN")
    target_link_libraries(${target} ${JEMALLOC_LIB})
  else()
    target_link_libraries(${target} PRIVATE ${JEMALLOC_LIB})
  endif()
  message(STATUS "Linking ${target} with jemalloc: ${JEMALLOC_LIB}")
endfunction()
