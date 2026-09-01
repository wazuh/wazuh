if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # wazuh-manager-service-control is Linux-only (see src/util/CMakeLists.txt).
    add_executable(test_manager_service_control test_manager_service_control.c)
    target_compile_definitions(
        test_manager_service_control PRIVATE WAZUH_RUNTIME_USER="wazuh-manager")
    target_link_libraries(test_manager_service_control -lcmocka -fprofile-arcs
                          -ftest-coverage)
    add_test(NAME test_manager_service_control COMMAND test_manager_service_control)
endif()
