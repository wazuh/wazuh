# WINAGENT NEEDS TO BE BUILT WITH WIN32 toolchain
# cmake ../ -DCMAKE_TOOLCHAIN_FILE=../Toolchain-win32.cmake -DTARGET=winagent

set(CMAKE_FIND_LIBRARY_SUFFIXES ".a;.dll")

if(NOT CMAKE_CROSSCOMPILING)
  message(FATAL_ERROR "Cross compiling tools not enabled. Try running cmake as: \n cmake ../ -DCMAKE_TOOLCHAIN_FILE=../Toolchain-win32.cmake")
endif()

# Setup the compiling toolchain
# Find the wazuh shared library
find_library(WAZUHEXT NAMES wazuhext HINTS "${SRC_FOLDER}")
set(uname "Win32")

if(NOT WAZUHEXT)
  message(FATAL_ERROR "WAZUHEXT is set to '${WAZUHEXT}', but did not find any file matching ${SRC_FOLDER}/${CMAKE_FIND_LIBRARY_PREFIXES}wazuhext${CMAKE_FIND_LIBRARY_SUFFIXES}")
  message(FATAL_ERROR "libwazuhext not found in ${SRC_FOLDER} Aborting...")
endif()

# Find the wazuh sysinfo library
find_library(SYSINFO NAMES sysinfo HINTS "${SRC_FOLDER}/data_provider/build/bin")
set(uname "Win32")

if(NOT SYSINFO)
  message(FATAL_ERROR "SYSINFO is set to '${SYSINFO}', but did not find any file matching ${SRC_FOLDER}/${CMAKE_FIND_LIBRARY_PREFIXES}sysinfo${CMAKE_FIND_LIBRARY_SUFFIXES}")
  message(FATAL_ERROR "libsysinfo not found in ${SRC_FOLDER}/data_provider/build/bin Aborting...")
endif()

# Win32 pthread library
find_library(PTHREAD NAMES libwinpthread-1.dll HINTS "${SRC_FOLDER}/win32")
if(NOT PTHREAD)
  message(FATAL_ERROR "libwinpthread-1.dll not found in ${SRC_FOLDER}/win32 Aborting...")
endif()

# Static cmocka
find_library(STATIC_CMOCKA NAMES libcmocka.a libcmocka-static.a HINTS "/usr/i686-w64-mingw32/sys-root/mingw/lib/" "/usr/i686-w64-mingw32/lib/")
if(NOT STATIC_CMOCKA)
  message(FATAL_ERROR "libcmocka.a not found in /usr/i686-w64-mingw32/sys-root/mingw/lib/ Aborting...")
endif()

# Add compiling flags
add_compile_options(-ggdb -O0 -g -coverage)
add_definitions(-DTEST_WINAGENT -DDEBUG -DENABLE_AUDIT -D_WIN32_WINNT=0x600 -DWAZUH_UNIT_TESTING)

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
file(GLOB os_execd_lib ${SRC_FOLDER}/os_execd/*.o ${SRC_FOLDER}/active-response/*.o)
list(APPEND obj_files ${os_execd_lib})

# Add win32 objects
file(GLOB win32_files ${SRC_FOLDER}/win32/win_service.o ${SRC_FOLDER}/win32/win_utils.o)
list(APPEND obj_files ${win32_files})

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
)

target_link_libraries(DEPENDENCIES_O ${WAZUHLIB} ${WAZUHEXT} ${PTHREAD} ${SYSINFO} ${STATIC_CMOCKA} wsock32 wevtapi shlwapi comctl32 advapi32 kernel32 psapi gdi32 iphlpapi ws2_32 crypt32 wintrust)

# Set tests dependencies
# Use --start-group and --end-group to handle circular dependencies
set(TEST_DEPS -Wl,--start-group ${WAZUHLIB} ${WAZUHEXT} ${SYSINFO} DEPENDENCIES_O -Wl,--end-group ${PTHREAD} ${STATIC_CMOCKA} wsock32 wevtapi shlwapi comctl32 advapi32 kernel32 psapi gdi32 iphlpapi ws2_32 crypt32 -fprofile-arcs -ftest-coverage)
set(TEST_EVENT_DEPS -Wl,--start-group ${WAZUHLIB} ${WAZUHEXT} ${SYSINFO} DEPENDENCIES_O -Wl,--end-group ${PTHREAD} ${STATIC_CMOCKA} wsock32 wevtapi shlwapi comctl32 advapi32 kernel32 psapi gdi32 iphlpapi ws2_32 crypt32 -fprofile-arcs -ftest-coverage)

add_subdirectory(client-agent)
add_subdirectory(wazuh_modules)
add_subdirectory(os_execd)
add_subdirectory(win32)
add_subdirectory(logcollector)
