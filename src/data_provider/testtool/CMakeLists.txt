project(sysinfo_test_tool)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    add_definitions(-DWIN32=1)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_executable(sysinfo_test_tool
               ${sysinfo_TESTTOOL_SRC}
               ${CMAKE_SOURCE_DIR}/data_provider/testtool/main.cpp)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(sysinfo_test_tool
        sysinfo
        psapi
        iphlpapi
        ws2_32
        -static-libstdc++
    )
elseif (CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
    target_link_libraries(sysinfo_test_tool
        sysinfo
        pthread)
elseif (CMAKE_SYSTEM_NAME STREQUAL "AIX")
    target_link_libraries(sysinfo_test_tool
        sysinfo
        dl
        pthread
    )
else()
    target_link_libraries(sysinfo_test_tool
        sysinfo
        dl
        pthread
        proc
    )

    if(SOLARIS)
        target_link_libraries(sysinfo_test_tool
            sysinfo
            nsl
            socket
        )
    endif(SOLARIS)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

if(APPLE)
  add_custom_command(TARGET sysinfo_test_tool
    POST_BUILD COMMAND
    ${CMAKE_INSTALL_NAME_TOOL} -change "@rpath/libsysinfo.dylib" "@executable_path/../lib/libsysinfo.dylib"
    $<TARGET_FILE:sysinfo_test_tool>)
add_custom_command(TARGET sysinfo_test_tool
    POST_BUILD COMMAND
    ${CMAKE_INSTALL_NAME_TOOL} -change "@rpath/libwazuhext.dylib" "@executable_path/../../../libwazuhext.dylib"
    $<TARGET_FILE:sysinfo_test_tool>)
endif(APPLE)
