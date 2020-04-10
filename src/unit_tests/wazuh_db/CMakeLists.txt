
list(APPEND wdb_tests_names "test_wdb_integrity")
list(APPEND wdb_tests_flags "-Wl,--wrap,_mdebug1 -Wl,--wrap,wdb_stmt_cache -Wl,--wrap,sqlite3_step -Wl,--wrap,sqlite3_errmsg \
                         -Wl,--wrap,EVP_DigestInit_ex -Wl,--wrap,EVP_DigestUpdate -Wl,--wrap,_DigestFinal_ex \
                         -Wl,--wrap,sqlite3_column_text -Wl,--wrap,_mdebug2")

# Add server specific tests to the list
list(APPEND wdb_tests_names "test_wdb_fim")
list(APPEND wdb_tests_flags "-Wl,--wrap,_merror -Wl,--wrap,_mdebug1 -Wl,--wrap,wdb_begin2 \
                         -Wl,--wrap,cJSON_GetStringValue -Wl,--wrap,cJSON_IsNumber \
                         -Wl,--wrap,cJSON_IsObject -Wl,--wrap,wdb_stmt_cache -Wl,--wrap,sqlite3_bind_text \
                         -Wl,--wrap,sqlite3_bind_int64 -Wl,--wrap,sqlite3_step")

list(APPEND wdb_tests_names "test_wdb_parser")
list(APPEND wdb_tests_flags "-Wl,--wrap,_minfo -Wl,--wrap,_mdebug2 -Wl,--wrap,_mdebug1 -Wl,--wrap,_merror -Wl,--wrap,_mwarn \
                         -Wl,--wrap,wdb_scan_info_get -Wl,--wrap,wdb_fim_update_date_entry -Wl,--wrap,wdb_fim_clean_old_entries \
                         -Wl,--wrap,wdb_scan_info_update -Wl,--wrap,wdb_scan_info_fim_checks_control -Wl,--wrap,wdb_syscheck_load \
                         -Wl,--wrap,wdb_fim_delete -Wl,--wrap,wdb_syscheck_save -Wl,--wrap,wdb_syscheck_save2 \
                         -Wl,--wrap,wdbi_query_checksum -Wl,--wrap,wdbi_query_clear -Wl,--wrap,wdb_open_agent2 -Wl,--wrap,wdb_leave \
                         -Wl,--wrap,wdb_inventory_save_hw -Wl,--wrap,wdb_inventory_save_os -Wl,--wrap,wdb_inventory_save_network -Wl,--wrap,wdb_inventory_delete_network \
                         -Wl,--wrap,wdb_inventory_save_program -Wl,--wrap,wdb_inventory_delete_program -Wl,--wrap,wdb_inventory_save_hotfix -Wl,--wrap,wdb_inventory_delete_hotfix \
                         -Wl,--wrap,wdb_inventory_save_port -Wl,--wrap,wdb_inventory_delete_port -Wl,--wrap,wdb_inventory_save_process -Wl,--wrap,wdb_inventory_delete_process \
                         -Wl,--wrap,wdb_inventory_save_scan_info")

list(APPEND wdb_tests_names "test_wdb_inventory")
list(APPEND wdb_tests_flags "-Wl,--wrap,_merror -Wl,--wrap,_mdebug1 -Wl,--wrap,wdb_hardware_save -Wl,--wrap,wdb_osinfo_save -Wl,--wrap,wdb_netinfo_save \
                         -Wl,--wrap,wdb_netproto_save -Wl,--wrap,wdb_netaddr_save -Wl,--wrap,wdb_netinfo_delete2 -Wl,--wrap,wdb_package_save \
                         -Wl,--wrap,wdb_package_delete2 -Wl,--wrap,wdb_hotfix_save -Wl,--wrap,wdb_set_hotfix_metadata -Wl,--wrap,wdb_hotfix_delete2 \
                         -Wl,--wrap,wdb_port_save -Wl,--wrap,wdb_port_delete2 -Wl,--wrap,wdb_process_save -Wl,--wrap,wdb_process_delete2 \
                         -Wl,--wrap,wdb_sys_scan_info_save")

# Compilig tests
list(LENGTH wdb_tests_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET wdb_tests_names ${counter} test_name)
    list(GET wdb_tests_flags ${counter} test_flags)

    add_executable(${test_name} ${test_name}.c)

    target_link_libraries(
        ${test_name}
        ${TEST_DEPS}
    )

    if(NOT test_flags STREQUAL " ")
        target_link_libraries(
            ${test_name}
            ${test_flags}
        )
    endif()
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
