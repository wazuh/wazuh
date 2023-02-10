project(syscollector_test_tool)

file(GLOB SYSCOLLECTOR_TESTTOOL_SRC
    "${CMAKE_SOURCE_DIR}/wazuh_modules/syscollector/testtool/*.cpp"
)

add_executable(syscollector_test_tool
    ${SYSCOLLECTOR_TESTTOOL_SRC}
)
add_definitions(-DWAZUH_UNIT_TESTING)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(syscollector_test_tool
        rsync
        dbsync
        sysinfo
        syscollector
        psapi
        iphlpapi
        crypto
        ssl
        ws2_32
        crypt32
        -static-libstdc++
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
    target_link_libraries(syscollector_test_tool
        rsync
        dbsync
        sysinfo
        syscollector
        pthread)
elseif(CMAKE_SYSTEM_NAME STREQUAL "AIX")
    target_link_libraries(syscollector_test_tool
        rsync
        dbsync
        sysinfo
        syscollector
        dl)
else()
    target_link_libraries(syscollector_test_tool
        rsync
        dbsync
        sysinfo
        syscollector
        dl
        proc
    )

    if(SOLARIS)
        target_link_libraries(syscollector_test_tool
            nsl
            socket
        )
    endif(SOLARIS)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
