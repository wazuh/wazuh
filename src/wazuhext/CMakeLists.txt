cmake_minimum_required(VERSION 3.9.6)

project(wazuhext)

get_filename_component(SRC_FOLDER     ${CMAKE_SOURCE_DIR}/ ABSOLUTE)

set(EXTERNAL_LIBS_PATHS)
set(EXTERNAL_LIBS)

# common libs
set(COMMON_LIBS_PATHS
    ${SRC_FOLDER}/external/cJSON/
    ${SRC_FOLDER}/external/zlib/
    ${SRC_FOLDER}/external/openssl/
    ${SRC_FOLDER}/external/sqlite/
    ${SRC_FOLDER}/external/libyaml/src/.libs/
    ${SRC_FOLDER}/external/libpcre2/.libs/)

set(COMMON_LIBS
    cjson
    z
    ssl
    crypto
    sqlite3
    yaml
    pcre2-8
    )

# apple libraries only
if(APPLE)
    set(APPLE_LIBS_PATHS
        ${SRC_FOLDER}/external/libplist/)
    set(APPLE_LIBS
        plist-2.0)
endif(APPLE)

# audit userspace libraries
if(USE_AUDIT AND LINUX)
    set(AUDIT_LIB_PATHS
        ${SRC_FOLDER}/external/audit-userspace/lib/.libs)
    set(AUDIT_LIB
        audit)
endif(USE_AUDIT AND LINUX)

# google tests libs
if(TEST)
    set(GTEST_LIBS_PATHS
        ${SRC_FOLDER}/external/googletest/lib/)
    set(GTEST_LIBS
        gtest
        gmock)
endif(TEST)

# manager only libs
if(${TARGET} STREQUAL "manager" OR ${TARGET} STREQUAL "server")
    set(MANAGER_LIBS_PATHS
        ${SRC_FOLDER}/external/bzip2/
        ${SRC_FOLDER}/external/libffi/server/.libs/)
    set(MANAGER_LIBS
        bz2
        ffi)
endif(${TARGET} STREQUAL "manager" OR ${TARGET} STREQUAL "server")

#Linux only libraries
if(LINUX)
    set(LINUX_LIBS_PATHS
        ${SRC_FOLDER}/external/procps
        ${SRC_FOLDER}/external/libdb/build_unix/.libs)
    set(LINUX_LIBS
        proc
        db-6.2
        dl)
    #not centos 5 libs
    if(NOT CENTOS5)
        set(ALPM_ARCHIVE_LIBS_PATHS
            ${SRC_FOLDER}/external/pacman/lib/libalpm/
            ${SRC_FOLDER}/external/libarchive/.libs/)
        set(ALPM_ARCHIVE_LIBS
            alpm
            archive)
    endif(NOT CENTOS5)
endif(LINUX)

# msg pack libraries
if(UNIX)
    set(UNIX_LIBS_PATHS
        ${SRC_FOLDER}/external/msgpack/)
    set(UNIX_LIBS
        msgpack)
endif(UNIX)

list(APPEND EXTERNAL_LIBS_PATHS ${COMMON_LIBS_PATHS} ${APPLE_LIBS} ${AUDIT_LIB_PATHS} ${GTEST_LIBS_PATHS} ${MANAGER_LIBS_PATHS} ${LINUX_LIBS_PATHS} ${ALPM_ARCHIVE_LIBS_PATHS} ${UNIX_LIBS_PATHS})
list(APPEND EXTERNAL_LIBS ${COMMON_LIBS} ${APPLE_LIBS} ${AUDIT_LIB} ${GTEST_LIBS} ${MANAGER_LIBS} ${LINUX_LIBS} ${ALPM_ARCHIVE_LIBS} ${UNIX_LIBS})

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

link_directories(${EXTERNAL_LIBS_PATHS})
add_library(wazuhext SHARED
            ${CMAKE_CURRENT_SOURCE_DIR}/empty.cpp)
target_link_libraries(wazuhext
                      -Wl,--whole-archive
                      ${EXTERNAL_LIBS}
                      -Wl,--no-whole-archive)

