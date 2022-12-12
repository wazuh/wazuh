project(data_provider_unit_test)

# Adding the data_provider tests to the general unit_test target
add_dependencies(unit_test ${PROJECT_NAME})

# All the data_provider tests will depend on this custom target
add_custom_target(${PROJECT_NAME})

include_directories(${CMAKE_SOURCE_DIR})

# Setting options for all the data_provider tests
add_compile_options(-O0 -g --coverage)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  link_libraries(-fprofile-arcs)
else()
  link_libraries(-lgcov)
endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_subdirectory(sysInfoPackagesLinuxHelper)
  add_subdirectory(sysInfoPackagesBerkeleyDB)
  add_subdirectory(sysInfoNetworkLinux)
  add_subdirectory(sysInfoNetworkSolaris)
  add_subdirectory(sysInfoRpmPackageManager)
  add_subdirectory(sysInfoPackageLinuxParserRpm)
  add_subdirectory(sysInfoPackagesSolaris)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  add_subdirectory(sysInfoNetworkBSD)
  add_subdirectory(sysInfoPackagesMAC)
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  add_subdirectory(sysInfoNetworkBSD)
elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  add_subdirectory(sysInfoNetworkBSD)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_subdirectory(sysInfoWin)
  add_subdirectory(sysInfoNetworkWindows)
endif(CMAKE_SYSTEM_NAME STREQUAL "Linux")

add_subdirectory(sysInfo)
add_subdirectory(sysInfoPorts)
