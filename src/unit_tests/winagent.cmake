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

# Add compiling flags
add_compile_options(-ggdb -O0 -g -coverage -DTEST_WINAGENT)

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

add_library(DEPENDENCIES_O SHARED ${obj_files})
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

target_link_libraries(DEPENDENCIES_O ${WAZUHLIB} ${WAZUHEXT} cmocka wsock32 wevtapi shlwapi comctl32 advapi32 kernel32 psapi gdi32 iphlpapi ws2_32 crypt32)

# Set tests dependencies
set(TEST_DEPS ${WAZUHLIB} ${WAZUHEXT} DEPENDENCIES_O cmocka wsock32 wevtapi shlwapi comctl32 advapi32 kernel32 psapi gdi32 iphlpapi ws2_32 crypt32 -fprofile-arcs -ftest-coverage)
