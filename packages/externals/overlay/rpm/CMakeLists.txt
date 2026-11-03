cmake_minimum_required(VERSION 3.12.4)
project(librpm)

# Configure basic options for minimal RPM build
set(ENABLE_NLS 0)
set(ENABLE_OPENMP 0)
set(ENABLE_PLUGINS 0)
set(ENABLE_NDB 1)
set(ENABLE_ASAN 0)

# Set basic function availability
set(HAVE_BASENAME 1)
set(HAVE_DIRNAME 1)
set(HAVE_GETCWD 1)
set(HAVE_GETLINE 1)
set(HAVE_LOCALTIME_R 1)
set(HAVE_FDATASYNC 1)
set(HAVE_FSTATAT 1)
set(HAVE_LINKAT 1)
set(HAVE_FCHMODAT 1)
set(HAVE_FCHOWNAT 1)
set(HAVE_GETADDRINFO 1)
set(HAVE_DIRENT_H 1)
set(HAVE_LIMITS_H 1)
set(HAVE_INTTYPES_H 1)
set(HAVE_SYS_UTSNAME_H 1)
set(HAVE_SYS_PARAM_H 1)
set(HAVE_SYS_STAT_H 1)
set(HAVE_SYS_SYSMACROS_H 1)
set(MAJOR_IN_SYSMACROS 1)
set(HAVE_UNISTD_H 1)
set(HAVE___PROGNAME 1)

# Configure config.h from config.h.in
configure_file(config.h.in config.h)

# Generate tagtbl.inc using the shell script
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/tagtbl.inc
    COMMAND /bin/sh ${CMAKE_CURRENT_SOURCE_DIR}/lib/gentagtbl.sh ${CMAKE_CURRENT_SOURCE_DIR}/include/rpm/rpmtag.h > ${CMAKE_CURRENT_BINARY_DIR}/tagtbl.inc
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/include/rpm/rpmtag.h ${CMAKE_CURRENT_SOURCE_DIR}/lib/gentagtbl.sh
    COMMENT "Generating tagtbl.inc"
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Collect all source files
file(GLOB_RECURSE RPM_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/lib/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/rpmio/*.c"
)

# Remove files that cause multiple definition conflicts or aren't needed
list(REMOVE_ITEM RPM_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/rpmio/digest_libgcrypt.c")  # No libgcrypt
list(REMOVE_ITEM RPM_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/rpmio/modemuncher.c")       # Included by lposix.c
list(REMOVE_ITEM RPM_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/rpmio/rpmpgp_sequoia.c")   # Conflicts with dummy
list(REMOVE_ITEM RPM_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/rpmio/rpmpgp_internal.c")  # May conflict

# Create static library
add_library(rpm STATIC
    ${RPM_SOURCES}
    ${CMAKE_CURRENT_BINARY_DIR}/tagtbl.inc
)

# Set compile definitions
target_compile_definitions(rpm PRIVATE
    HAVE_CONFIG_H
    _GNU_SOURCE
    RPM_CONFIGDIR="/usr/lib/rpm"
    SYSCONFDIR="/usr/etc"
    LOCALSTATEDIR="/usr/var"
    LOCALEDIR="/usr/share/locale"
    LIBRPMALIAS_EXECPATH="/usr/bin"
    LIBRPMALIAS_FILENAME="rpmpopt-4.16.1.2"
    _REENTRANT
    PIC
)

# Set include directories
target_include_directories(rpm PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}"      # For generated config.h
    "${CMAKE_CURRENT_SOURCE_DIR}/misc" # For system.h
    "${CMAKE_CURRENT_SOURCE_DIR}"      # Root directory
    "${CMAKE_CURRENT_SOURCE_DIR}/lib"  # For internal headers
    "${CMAKE_CURRENT_SOURCE_DIR}/include" # For public headers
    "${CMAKE_CURRENT_SOURCE_DIR}/rpmio"   # For rpmio headers
    "../lua/install/include"               # For lua headers
)

# Set output location and copy headers for Wazuh to use
set_target_properties(rpm PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    OUTPUT_NAME "rpm"
)

# Create output directory for headers
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/output/include/rpm")

# Copy all RPM headers to output directory so Wazuh can find them
file(GLOB RPM_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/include/rpm/*.h")
add_custom_target(rpm_headers ALL
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${RPM_HEADERS} "${CMAKE_CURRENT_BINARY_DIR}/output/include/rpm/"
    # Also copy some internal headers that might be needed
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/rpmio/rpmlua.h" "${CMAKE_CURRENT_BINARY_DIR}/output/include/rpm/"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/rpmio/lposix.h" "${CMAKE_CURRENT_BINARY_DIR}/output/include/rpm/"
    DEPENDS ${RPM_HEADERS}
    COMMENT "Copying RPM headers"
)
add_dependencies(rpm rpm_headers)
