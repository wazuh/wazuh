# Sets the RPATH for a Wazuh daemon or CLI tool.
#
# Release:        $ORIGIN/../lib            (clean, portable)
# Debug/sanitize: build-tree libs first     (run from src/build/bin/ as-is)
# Windows:        no-op (PE has no RPATH)
#
# Usage: wazuh_set_runtime_rpath(<target>)

function(wazuh_set_runtime_rpath target)
  if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    return()
  endif()

  if(APPLE)
    set(install_rpath "@executable_path/../lib")
  else()
    set(install_rpath "$ORIGIN/../lib")
  endif()

  if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR FSANITIZE)
    list(PREPEND install_rpath
      "${CMAKE_SOURCE_DIR}/build/lib"
      "${CMAKE_SOURCE_DIR}/external/rocksdb/build"
      "${CMAKE_SOURCE_DIR}/external/jemalloc/lib")
  endif()

  set_target_properties(${target} PROPERTIES
    INSTALL_RPATH "${install_rpath}"
    BUILD_WITH_INSTALL_RPATH TRUE)
endfunction()
