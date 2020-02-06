# Setup the compiling toolchain
set(CMAKE_SYSTEM_NAME Windows)

set(COMPILER_PREFIX "i686-w64-mingw32")
set(CMAKE_C_COMPILER ${COMPILER_PREFIX}-gcc)
# set(CMAKE_FIND_ROOT_PATH  /usr/${COMPILER_PREFIX} ${CMAKE_SOURCE_DIR}/../../)
set(CMAKE_C_LINK_EXECUTABLE "${CMAKE_C_COMPILER} <FLAGS> <CMAKE_C_LINK_FLAGS> <LINK_FLAGS> <OBJECTS>  -o <TARGET> <LINK_LIBRARIES>")
set(CMAKE_AR i686-w64-mingw32-ar)
set(CMAKE_RANLIB i686-w64-mingw32-ranlib)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

set(CMAKE_FIND_LIBRARY_PREFIXES "")
set(CMAKE_FIND_LIBRARY_SUFFIXES ".lib" ".dll" ".a")

# Find the wazuh shared library
find_library(WAZUHEXT NAMES libwazuhext.dll HINTS "${SRC_FOLDER}")
if(NOT WAZUHEXT)
  message(FATAL_ERROR "libwazuhext not found! Aborting...")
endif()

# Add compiling flags
add_compile_options(-ggdb -O0 -g -coverage -DTEST_WINAGENT)

# Generate win32 library
file(GLOB win32_files ../win32/win_service_rk.o)
add_library(WIN32_O SHARED ${win32_files})
set_source_files_properties(
    ${win32_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    WIN32_O
    PROPERTIES
    LINKER_LANGUAGE C
    CMAKE_C_COMPILER i686-w64-mingw32-gcc
    CMAKE_C_LINK_EXECUTABLE "CMAKE_C_COMPILER <FLAGS> <CMAKE_C_LINK_FLAGS> <LINK_FLAGS> <OBJECTS>  -o <TARGET> <LINK_LIBRARIES>"
)

target_link_libraries(WIN32_O ${WAZUHLIB} ${WAZUHEXT} -lwsock32 -lwevtapi -lshlwapi -lcomctl32 -ladvapi32 -lkernel32 -lpsapi -lgdi32 -liphlpapi -lws2_32 -lcrypt32)

# Set tests dependencies
set(TEST_DEPS SYSC SYSCHECK_O WIN32_O -lcmocka -fprofile-arcs -ftest-coverage)
