cmake_minimum_required(VERSION 3.12.4)

project(sysInfoHardwareMac_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

file(GLOB sysinfo_UNIT_TEST_SRC
    "${CMAKE_SOURCE_DIR}/src/hardware/*X86_64Mac.cpp"
    "sysInfoHardwareMac_test.cpp"
    "sysInfoHardwareWrapperMac_test.cpp"
    "main.cpp")

add_executable(sysInfoHardwareMac_unit_test
    ${sysinfo_UNIT_TEST_SRC})

target_link_libraries(sysInfoHardwareMac_unit_test
    debug gtestd
    debug gmockd
    debug gtest_maind
    debug gmock_maind
    optimized gtest
    optimized gmock
    optimized gtest_main
    optimized gmock_main
    pthread
    cjson
)

add_test(NAME sysInfoHardwareMac_unit_test
         COMMAND sysInfoHardwareMac_unit_test)

if(${CMAKE_HOST_SYSTEM_PROCESSOR} MATCHES "arm64.*|ARM64.*")
    file(GLOB sysinfo_ARM_UNIT_TEST_SRC
        "${CMAKE_SOURCE_DIR}/src/hardware/*ARMMac.cpp"
        "sysInfoHardwareWrapperARMMac_test.cpp"
        "main.cpp")

    add_executable(sysInfoHardwareARMMac_unit_test
        ${sysinfo_ARM_UNIT_TEST_SRC})

    find_library(iokit_lib IOKit)
    if(NOT iokit_lib)
        message(FATAL_ERROR "IOKit library not found! Aborting...")
    endif()
    find_library(corefoundation_lib CoreFoundation)
    if(NOT corefoundation_lib)
        message(FATAL_ERROR "CoreFoundation library not found! Aborting...")
    endif()
        
    target_link_libraries(sysInfoHardwareARMMac_unit_test
        debug gtestd
        debug gmockd
        debug gtest_maind
        debug gmock_maind
        optimized gtest
        optimized gmock
        optimized gtest_main
        optimized gmock_main
        pthread
        cjson
        ${iokit_lib}
        ${corefoundation_lib}
    )

    add_test(NAME sysInfoHardwareARMMac_unit_test
            COMMAND sysInfoHardwareARMMac_unit_test)
endif()
