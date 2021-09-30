cmake_minimum_required(VERSION 3.12.4)

project(syscheck_db_testtool)
# Set the deps folder and the src folder.
get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../../ ABSOLUTE)
set(DEPS_FOLDER "${SRC_FOLDER}/external/")
# Get all the dependencies from the deps folder.
file(GLOB DEPS "${DEPS_FOLDER}*/")

include_directories(${CMAKE_SOURCE_DIR}/)
include_directories(${DEPS})
include_directories("${DEPS_FOLDER}/openssl/include")
include_directories(${CMAKE_SOURCE_DIR}/testtool/)
include_directories(${SRC_FOLDER}/shared_modules/common/)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/rsync/include/)
include_directories(${SRC_FOLDER}/config)
include_directories(${SRC_FOLDER}/syscheckd/)
include_directories(${SRC_FOLDER}/syscheckd/db/include/)
include_directories(${SRC_FOLDER}/headers/)
include_directories(${SRC_FOLDER})

link_directories(${SRC_FOLDER}/shared_modules/dbsync/build/lib)
link_directories(${SRC_FOLDER}/shared_modules/rsync/build/lib)
link_directories(${SRC_FOLDER}/syscheckd/db/build/lib)

if(COVERITY)
  add_definitions(-D__GNUC__=8)
endif(COVERITY)

set(CMAKE_CXX_FLAGS "-g -Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -std=c++14 -pthread")

if(FSANITIZE)
  set(CMAKE_CXX_FLAGS_DEBUG "-fsanitize=address,leak,undefined")
endif(FSANITIZE)
file(GLOB FIMDB_TESTTOOL
        "${SRC_FOLDER}/syscheckd/db/testtool/*.cpp"
        )

add_executable(fimdb_testtool
               ${FIMDB_TESTTOOL}
               )

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(fimdb_testtool
        rsync
        dbsync
        crypto
        ssl
        ws2_32
        crypt32
        -static-libstdc++
    )
elseif (CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
    target_link_libraries(fimdb_testtool
        rsync
        dbsync
        fimdb
        pthread
    )
elseif (CMAKE_SYSTEM_NAME STREQUAL "AIX")
    target_link_libraries(fimdb_testtool
        rsync
        dbsync
        fimdb
    )
else()
    target_link_libraries(fimdb_testtool
        rsync
        dbsync
        fimdb
    )

    if(SOLARIS)
        target_link_libraries(fimdb_testtool
            nsl
            socket
            fimdb
        )
    endif(SOLARIS)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
