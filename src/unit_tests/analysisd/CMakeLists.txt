# Generate analysisd library
file(GLOB analysisd_files
    ${SRC_FOLDER}/analysisd/*.o
    ${SRC_FOLDER}/analysisd/alerts/*.o
    ${SRC_FOLDER}/analysisd/cdb/*.o
    ${SRC_FOLDER}/analysisd/compiled_rules/*.o
    ${SRC_FOLDER}/analysisd/decoders/*.o
    ${SRC_FOLDER}/analysisd/output/*.o
    ${SRC_FOLDER}/analysisd/format/*.o
    ${SRC_FOLDER}/analysisd/decoders/plugins/*.o
    ${SRC_FOLDER}/analysisd/format/*.o
    ${SRC_FOLDER}/analysisd/output/*.o
   )

add_library(ANALYSISD_O STATIC ${analysisd_files})

include_directories(${SRC_FOLDER}/analysisd)

set_source_files_properties(
    ${analysisd_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    ANALYSISD_O
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(ANALYSISD_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

# Generate Analysisd tests
list(APPEND analysisd_names "test_analysisd_syscheck")
list(APPEND analysisd_flags "-Wl,--wrap,wdbc_query_ex -Wl,--wrap,wdbc_parse_result ${DEBUG_OP_WRAPPERS}")

list(APPEND analysisd_names "test_cleanevent")
list(APPEND analysisd_flags "${DEBUG_OP_WRAPPERS}")

list(APPEND analysisd_names "test_dbsync")
list(APPEND analysisd_flags "-Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,OS_SendSecureTCP \
                         -Wl,--wrap,connect_to_remoted -Wl,--wrap,send_msg_to_agent -Wl,--wrap,wdbc_query_ex \
                         -Wl,--wrap,wdbc_parse_result ${DEBUG_OP_WRAPPERS}")

list(APPEND analysisd_names "test_exec")
list(APPEND analysisd_flags "-Wl,--wrap,OS_SendUnix -Wl,--wrap,wdb_get_agent_info -Wl,--wrap,Eventinfo_to_jsonstr \
                             -Wl,--wrap,OS_ReadXML -Wl,--wrap,OS_GetOneContentforElement -Wl,--wrap,OS_ClearXML -Wl,--wrap,StartMQ \
                             -Wl,--wrap,wdb_get_agents_by_connection_status -Wl,--wrap,labels_find -Wl,--wrap,labels_get -Wl,--wrap,labels_free \
                             -Wl,--wrap,OS_IPFoundList \
                             -Wl,--wrap,OSMatch_Execute \
                             -Wl,--wrap,OSRegex_Compile -Wl,--wrap,OSRegex_Execute_ex -Wl,--wrap,OSRegex_Execute \
                             ${DEBUG_OP_WRAPPERS}")

list(APPEND analysisd_names "test_log")
list(APPEND analysisd_flags "-Wl,--wrap,fprintf,-wrap,fflush,--wrap,fclose,--wrap,fgets,--wrap,fgetpos,--wrap,fopen \
                             -Wl,--wrap,fread,--wrap,fseek,--wrap,fwrite,--wrap,remove,--wrap,fgetc,--wrap,fputc \
                             -Wl,--wrap,ctime_r -Wl,--wrap,wfopen -Wl,--wrap,popen")

list(APPEND analysisd_names "test_labels")
list(APPEND analysisd_flags "-Wl,--wrap,wdb_get_agent_labels")

list(APPEND analysisd_names "test_mitre")
list(APPEND analysisd_flags "-Wl,--wrap,wdbc_connect_with_attempts -Wl,--wrap,wdbc_query_ex \
                             -Wl,--wrap,wdbc_query_parse_json ${HASH_OP_WRAPPERS} ${DEBUG_OP_WRAPPERS}")

list(APPEND analysisd_names "test_rules")
LIST(APPEND analysisd_flags "-Wl,--wrap,_mwarn -Wl,--wrap,_merror -Wl,--wrap,_os_analysisd_add_logmsg \
                             -Wl,--wrap,OS_ClearNode -Wl,--wrap,w_get_attr_val_by_name ${DEBUG_OP_WRAPPERS}")

LIST(APPEND analysisd_names "test_same_different_loop")
LIST(APPEND analysisd_flags "-W")

LIST(APPEND analysisd_names "test_logtest")
LIST(APPEND analysisd_flags "-Wl,--wrap,ReadConfig -Wl,--wrap,_merror -Wl,--wrap,OS_BindUnixDomain -Wl,--wrap,OSHash_Create \
                             -Wl,--wrap,pthread_mutex_init -Wl,--wrap,_minfo -Wl,--wrap,_w_mutex_init -Wl,--wrap,w_create_thread \
                             -Wl,--wrap,mutex_destroy -Wl,--wrap,close -Wl,--wrap,getDefine_Int -Wl,--wrap,OSList_Create \
                             -Wl,--wrap,OSList_SetMaxSize -Wl,--wrap,OSHash_setSize -Wl,--wrap,OSHash_Delete_ex \
                             -Wl,--wrap,OSHash_Free -Wl,--wrap,os_remove_rules_list -Wl,--wrap,os_remove_decoders_list \
                             -Wl,--wrap,os_remove_cdblist -Wl,--wrap,os_remove_cdbrules -Wl,--wrap,os_remove_eventlist \
                             -Wl,--wrap,sleep -Wl,--wrap,OSHash_Begin -Wl,--wrap,OSHash_Begin_ex -Wl,--wrap,time -Wl,--wrap,difftime \
                             -Wl,--wrap,OSHash_Next -Wl,--wrap,FOREVER -Wl,--wrap,OS_CreateEventList \
                             -Wl,--wrap,ReadDecodeXML -Wl,--wrap,Lists_OP_LoadList -Wl,--wrap,Lists_OP_MakeAll \
                             -Wl,--wrap,Rules_OP_ReadRules -Wl,--wrap,OS_ListLoadRules -Wl,--wrap,_setlevels \
                             -Wl,--wrap,AddHash_Rule -Wl,--wrap,Accumulate_Init -Wl,--wrap,OSStore_Free \
                             -Wl,--wrap,SetDecodeXML -Wl,--wrap,randombytes -Wl,--wrap,cJSON_IsNumber \
                             -Wl,--wrap,cJSON_GetObjectItemCaseSensitive -Wl,--wrap,_mdebug1 \
                             -Wl,--wrap,_os_analysisd_add_logmsg -Wl,--wrap,OSHash_Get_ex -Wl,--wrap,pthread_mutex_lock \
                             -Wl,--wrap,pthread_mutex_unlock -Wl,--wrap,OSHash_Add_ex -Wl,--wrap,OSList_GetFirstNode \
                             -Wl,--wrap,cJSON_CreateArray -Wl,--wrap,cJSON_AddItemToObject -Wl,--wrap,wm_strcat \
                             -Wl,--wrap,cJSON_CreateString -Wl,--wrap,cJSON_AddItemToArray \
                             -Wl,--wrap,os_analysisd_free_log_msg -Wl,--wrap,OSList_DeleteCurrentlyNode \
                             -Wl,--wrap,os_analysisd_string_log_msg -Wl,--wrap,cJSON_ParseWithOpts \
                             -Wl,--wrap,cJSON_IsString -Wl,--wrap,cJSON_DeleteItemFromObjectCaseSensitive \
                             -Wl,--wrap,cJSON_CreateObject -Wl,--wrap,cJSON_AddNumberToObject  \
                             -Wl,--wrap,cJSON_PrintUnformatted -Wl,--wrap,cJSON_Delete \
                             -Wl,--wrap,pthread_mutex_destroy -Wl,--wrap,cJSON_IsObject -Wl,--wrap,DecodeEvent \
                             -Wl,--wrap,cJSON_GetStringValue -Wl,--wrap,OS_CleanMSG -Wl,--wrap,cJSON_GetObjectItem \
                             -Wl,--wrap,OS_CheckIfRuleMatch -Wl,--wrap,OS_AddEvent -Wl,--wrap,IGnore \
                             -Wl,--wrap,OSList_AddData -Wl,--wrap,accept -Wl,--wrap,OS_RecvSecureTCP \
                             -Wl,--wrap,OS_SendSecureTCP -Wl,--wrap,CreateThreadJoinable -Wl,--wrap,_merror_exit \
                             -Wl,--wrap,CreateThread -Wl,--wrap,pthread_join -Wl,--wrap,unlink \
                             -Wl,--wrap,Eventinfo_to_jsonstr -Wl,--wrap,cJSON_Parse -Wl,--wrap,ParseRuleComment \
                             -Wl,--wrap,Accumulate -Wl,--wrap,cJSON_AddStringToObject -Wl,--wrap,cJSON_AddBoolToObject \
                             -Wl,--wrap,OSHash_SetFreeDataPointer -Wl,--wrap,OSHash_Delete \
                             -Wl,--wrap,pthread_rwlock_init -Wl,--wrap,pthread_rwlock_rdlock \
                             -Wl,--wrap,pthread_rwlock_unlock -Wl,--wrap,pthread_rwlock_wrlock \
                             -Wl,--wrap,pthread_mutex_trylock -Wl,--wrap,OSHash_Get -Wl,--wrap,OSHash_Add \
                             -Wl,--wrap,OSList_CleanOnlyNodes -Wl,--wrap,w_analysisd_accumulate_free \
                             -Wl,--wrap,w_get_attr_val_by_name -Wl,--wrap,OS_GetElementsbyNode -Wl,--wrap,OS_ClearNode \
                             -Wl,--wrap,OS_ClearXML -Wl,--wrap,OS_ReadXML -Wl,--wrap,Read_Rules -Wl,--wrap,Read_Alerts")

LIST(APPEND analysisd_names "test_logtest-config")
LIST(APPEND analysisd_flags "-Wl,--wrap,get_nproc -Wl,--wrap,cJSON_CreateObject \
                             -Wl,--wrap,cJSON_AddStringToObject -Wl,--wrap,cJSON_AddNumberToObject -Wl,--wrap,cJSON_AddItemToObject \
                             ${DEBUG_OP_WRAPPERS}")

LIST(APPEND analysisd_names "test_analysisd_hotreload")
LIST(APPEND analysisd_flags "${DEBUG_OP_WRAPPERS} -Wl,--wrap,RootcheckHotReload -Wl,--wrap,SyscollectorHotReload        \
                            -Wl,--wrap,CiscatHotReload -Wl,--wrap,HostinfoHotReload -Wl,--wrap,WinevtHotReload         \
                            -Wl,--wrap,SecurityConfigurationAssessmentHotReload -Wl,--wrap,fim_hot_reload                \
                            -Wl,--wrap,_os_analysisd_add_logmsg -Wl,--wrap,w_analysisd_accumulate_free                 \
                            -Wl,--wrap,w_get_attr_val_by_name -Wl,--wrap,OS_GetElementsbyNode -Wl,--wrap,OS_ClearNode  \
                            -Wl,--wrap,OS_ReadXML -Wl,--wrap,OS_ClearXML -Wl,--wrap,OSList_CleanOnlyNodes              \
                            -Wl,--wrap,OS_CreateEventList -Wl,--wrap,ReadDecodeXML -Wl,--wrap,SetDecodeXML             \
                            -Wl,--wrap,Lists_OP_LoadList -Wl,--wrap,Lists_OP_MakeAll -Wl,--wrap,Rules_OP_ReadRules     \
                            -Wl,--wrap,OS_ListLoadRules -Wl,--wrap,_setlevels -Wl,--wrap,AddHash_Rule                  \
                            -Wl,--wrap,Accumulate_Init -Wl,--wrap,OSStore_Free -Wl,--wrap,OSHash_Create                \
                            -Wl,--wrap,OSHash_Free -Wl,--wrap,FTS_HotReload -Wl,--wrap,Read_Rules")

LIST(APPEND analysisd_names "test_decoder_list")
LIST(APPEND analysisd_flags "-Wl,--wrap,FreeDecoderInfo")

LIST(APPEND analysisd_names "test_decode-xml")
LIST(APPEND analysisd_flags "-Wl,--wrap,_os_analysisd_add_logmsg -Wl,--wrap,OSStore_Create \
                             -Wl,--wrap,OSStore_Put_ex ${DEBUG_OP_WRAPPERS}")

LIST(APPEND analysisd_names "test_lists_list")
LIST(APPEND analysisd_flags "-Wl,--wrap,OSMatch_FreePattern")

LIST(APPEND analysisd_names "test_rule_list")
LIST(APPEND analysisd_flags "-Wl,--wrap,OSMatch_FreePattern -Wl,--wrap,OSRegex_FreePattern -Wl,--wrap,os_remove_cdbrules \
                            -Wl,--wrap,_os_analysisd_add_logmsg -Wl,--wrap,OS_IsValidIP")

LIST(APPEND analysisd_names "test_eventinfo_list")
LIST(APPEND analysisd_flags "-Wl,--wrap,Free_Eventinfo")

LIST(APPEND analysisd_names "test_logmsg")
LIST(APPEND analysisd_flags "-Wl,--wrap,isDebug -Wl,--wrap,OSList_AddData -Wl,--wrap,vsnprintf -Wl,--wrap,_mverror \
                             -Wl,--wrap,_mverror -Wl,--wrap,_mvinfo -Wl,--wrap,_mvwarn")
LIST(APPEND analysisd_names "test_decoder_rootcheck")
LIST(APPEND analysisd_flags "-Wl,--wrap,send_rootcheck_log ${DEBUG_OP_WRAPPERS}")

LIST(APPEND analysisd_names "test_decoder_syscollector")
LIST(APPEND analysisd_flags "-Wl,--wrap,wdbc_query_ex ${DEBUG_OP_WRAPPERS}")

LIST(APPEND analysisd_names "test_decoder_winevtchannel")
LIST(APPEND analysisd_flags "${DEBUG_OP_WRAPPERS} -Wl,--wrap,cJSON_ParseWithOpts -Wl,--wrap,cJSON_GetObjectItem        \
                              -Wl,--wrap,cJSON_Delete -Wl,--wrap,cJSON_AddStringToObject -Wl,--wrap,cJSON_CreateObject \
                              -Wl,--wrap,cJSON_PrintUnformatted -Wl,--wrap,cJSON_AddItemToObject -Wl,--wrap,cJSON_AddStringToObject                      \
                              -Wl,--wrap,JSON_Decoder_Exec                                                             \
                              -Wl,--wrap,OS_ReadXMLString -Wl,--wrap,OS_GetElementsbyNode -Wl,--wrap,OS_ClearXML       \
                              -Wl,--wrap,w_get_attr_val_by_name")

LIST(APPEND analysisd_names "test_decoder_winevtchannel_input")
LIST(APPEND analysisd_flags "${DEBUG_OP_WRAPPERS}")


list(APPEND analysisd_names "test_analysis-state")
list(APPEND analysisd_flags "-Wl,--wrap,time -Wl,--wrap,rem_get_qsize -Wl,--wrap,rem_get_tsize \
                            -Wl,--wrap,OSHash_Create -Wl,--wrap,OSHash_Add -Wl,--wrap,OSHash_Add_ex -Wl,--wrap,OSHash_Begin -Wl,--wrap,OSHash_Begin_ex \
                            -Wl,--wrap,OSHash_Delete_ex -Wl,--wrap,OSHash_Delete -Wl,--wrap,OSHash_Get -Wl,--wrap,OSHash_Clean \
                            -Wl,--wrap,OSHash_Get_ex -Wl,--wrap,OSHash_Next -Wl,--wrap,OSHash_SetFreeDataPointer \
                            -Wl,--wrap,OSHash_Update_ex -Wl,--wrap,OSHash_Update -Wl,--wrap,OSHash_Get_Elem_ex \
                            -Wl,--wrap,wdb_get_agents_ids_of_current_node -Wl,--wrap,_merror -Wl,--wrap,limit_reached")

list(APPEND analysisd_names "test_asyscom")
list(APPEND analysisd_flags "-Wl,--wrap,asys_create_state_json -Wl,--wrap,OS_BindUnixDomain -Wl,--wrap,select -Wl,--wrap,close -Wl,--wrap,accept \
                             -Wl,--wrap,OS_RecvSecureTCP -Wl,--wrap,OS_SendSecureTCP -Wl,--wrap,getGlobalConfig -Wl,--wrap,asys_create_agents_state_json \
                             -Wl,--wrap,wdb_get_agents_ids_of_current_node -Wl,--wrap,json_parse_agents -Wl,--wrap,getpid ${DEBUG_OP_WRAPPERS}")

LIST(APPEND analysisd_names "test_limits")
LIST(APPEND analysisd_flags "-Wl,--wrap,_minfo -Wl,--wrap,_mwarn")

list(LENGTH analysisd_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET analysisd_names ${counter} analysisd_test_name)
    list(GET analysisd_flags ${counter} analysisd_test_flags)

    add_executable(${analysisd_test_name} ${analysisd_test_name}.c)

    target_link_libraries(
        ${analysisd_test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        ANALYSISD_O
        ${TEST_DEPS}
    )

    if(NOT analysisd_test_flags STREQUAL " ")
        target_link_libraries(
            ${analysisd_test_name}
            ${analysisd_test_flags}
        )
    endif()
    add_test(NAME ${analysisd_test_name} COMMAND ${analysisd_test_name})
endforeach()
