# WINAGENT NEEDS TO BE BUILT WITH WIN32 toolchain
# cmake ../ -DCMAKE_TOOLCHAIN_FILE=../Toolchain-win32.cmake

if(NOT CMAKE_CROSSCOMPILING)
  message(FATAL_ERROR "Cross compiling tools not enabled. Try running cmake as: \n cmake ../ -DCMAKE_TOOLCHAIN_FILE=../Toolchain-win32.cmake")
endif()

# Setup the compiling toolchain
# Find the wazuh shared library
find_library(WAZUHEXT NAMES libwazuhext.dll HINTS "${SRC_FOLDER}")
if(NOT WAZUHEXT)
  message(FATAL_ERROR "libwazuhext not found in ${SRC_FOLDER} Aborting...")
endif()

# Win32 pthread library
find_library(PTHREAD NAMES libwinpthread-1.dll HINTS "${SRC_FOLDER}/win32")
if(NOT PTHREAD)
  message(FATAL_ERROR "libwinpthread-1.dll not found in ${SRC_FOLDER}/win32 Aborting...")
endif()

# Static cmocka
find_library(STATIC_CMOCKA NAMES libcmocka.a HINTS "/usr/i686-w64-mingw32/sys-root/mingw/lib/" "/usr/i686-w64-mingw32/lib/")
if(NOT STATIC_CMOCKA)
  message(FATAL_ERROR "libcmocka.a not found in /usr/i686-w64-mingw32/sys-root/mingw/lib/ Aborting...")
endif()

# Add compiling flags
add_compile_options(-ggdb -O0 -g -coverage -DTEST_WINAGENT -DDEBUG -DENABLE_AUDIT)

# Add syscheck objects
file(GLOB sysfiles ${SRC_FOLDER}/syscheckd/*.o)
list(REMOVE_ITEM sysfiles ${SRC_FOLDER}/syscheckd/main.o)
list(FILTER sysfiles EXCLUDE REGEX ".*-event.o$")
list(APPEND obj_files ${sysfiles})


file(GLOB rootfiles ${SRC_FOLDER}/rootcheck/*.o)
list(FILTER rootfiles EXCLUDE REGEX ".*_rk.o$")
list(APPEND obj_files ${rootfiles})

# Add logcollector objects
file(GLOB logcollector_lib ${SRC_FOLDER}/logcollector/*.o)
list(FILTER logcollector_lib EXCLUDE REGEX ".*-event.o$")
list(APPEND obj_files ${logcollector_lib})

# Add monitord objects
file(GLOB monitord_lib ${SRC_FOLDER}/monitord/*.o)
list(REMOVE_ITEM monitord_lib ${SRC_FOLDER}/monitord/main.o)
list(APPEND obj_files ${monitord_lib})

# Add client-agent objects
file(GLOB client_agent_lib ${SRC_FOLDER}/client-agent/*.o)
list(REMOVE_ITEM client_agent_lib ${SRC_FOLDER}/client-agent/main.o)
list(APPEND obj_files ${client_agent_lib})

# Add execd objects
file(GLOB os_execd_lib ${SRC_FOLDER}/os_execd/*.o)
list(APPEND obj_files ${os_execd_lib})

# Add win32 objects
file(GLOB win32_files ${SRC_FOLDER}/win32/win_service.o ${SRC_FOLDER}/win32/win_utils.o)
list(APPEND obj_files ${win32_files})

# Add test wrappers
file(GLOB test_wrapper_files ${SRC_FOLDER}/unit_tests/wrappers/syscheckd/*.o)
list(APPEND obj_files ${test_wrapper_files})

add_library(DEPENDENCIES_O STATIC ${obj_files})
set_source_files_properties(
  ${obj_files}
  PROPERTIES
  EXTERNAL_OBJECT true
  GENERATED true
  )
set_target_properties(
  DEPENDENCIES_O
  PROPERTIES
  LINKER_LANGUAGE C
  CMAKE_C_COMPILER i686-w64-mingw32-gcc
  CMAKE_C_LINK_EXECUTABLE "CMAKE_C_COMPILER <FLAGS> <CMAKE_C_LINK_FLAGS> <LINK_FLAGS> <OBJECTS>  -o <TARGET> <LINK_LIBRARIES>"
)

target_link_libraries(DEPENDENCIES_O ${WAZUHLIB} ${WAZUHEXT} ${PTHREAD} ${STATIC_CMOCKA} wsock32 wevtapi shlwapi comctl32 advapi32 kernel32 psapi gdi32 iphlpapi ws2_32 crypt32)

# Set tests dependencies
# Use --start-group and --end-group to handle circular dependencies
set(TEST_DEPS -Wl,--start-group ${WAZUHLIB} ${WAZUHEXT} DEPENDENCIES_O -Wl,--end-group ${PTHREAD} ${STATIC_CMOCKA} wsock32 wevtapi shlwapi comctl32 advapi32 kernel32 psapi gdi32 iphlpapi ws2_32 crypt32 -fprofile-arcs -ftest-coverage)
