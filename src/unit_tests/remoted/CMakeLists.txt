# Generate remoted library
file(GLOB remoted_files
    ${SRC_FOLDER}/remoted/*.o)

add_library(REMOTED_O STATIC ${remoted_files})

set_source_files_properties(
    ${remoted_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    REMOTED_O
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(REMOTED_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

# Generate remoted tests
list(APPEND remoted_names "test_manager")
list(APPEND remoted_flags "-Wl,--wrap,_mdebug2 -Wl,--wrap,_mdebug1 -Wl,--wrap,w_parser_get_agent \
                            -Wl,--wrap,get_agent_group -Wl,--wrap,set_agent_group -Wl,--wrap,_merror \
                            -Wl,--wrap,MergeAppendFile -Wl,--wrap,OS_MoveFile -Wl,--wrap,w_parser_get_group \
                            -Wl,--wrap,wurl_request -Wl,--wrap,TestUnmergeFiles -Wl,--wrap,OS_MD5_File \
                            -Wl,--wrap,OSHash_Delete_ex -Wl,--wrap,OSHash_Delete -Wl,--wrap,OSHash_Get \
                            -Wl,--wrap,OSHash_Get_ex -Wl,--wrap,OSHash_Next -Wl,--wrap,OSHash_SetFreeDataPointer \
                            -Wl,--wrap,OSHash_Update_ex -Wl,--wrap,OSHash_Update -Wl,--wrap,OSHash_Get_Elem_ex \
                            -Wl,--wrap,OSHash_Create -Wl,--wrap,OSHash_Add -Wl,--wrap,OSHash_Add_ex \
                            -Wl,--wrap,checkBinaryFile -Wl,--wrap,OSHash_Set -Wl,--wrap,_minfo \
                            -Wl,--wrap,opendir -Wl,--wrap,cldir_ex -Wl,--wrap,wreaddir -Wl,--wrap=_mwarn \
                            -Wl,--wrap,closedir -Wl,--wrap,OSHash_Clean -Wl,--wrap,rmdir_ex \
                            -Wl,--wrap,OS_SHA256_String -Wl,--wrap,readdir -Wl,--wrap,strerror \
                            -Wl,--wrap,fopen -Wl,--wrap,fread -Wl,--wrap,fwrite -Wl,--wrap,fclose -Wl,--wrap,remove \
                            -Wl,--wrap,fgets -Wl,--wrap,fflush -Wl,--wrap,fseek -Wl,--wrap,fgetpos -Wl,--wrap=fgetc \
                            -Wl,--wrap,w_copy_file -Wl,--wrap,OSHash_Begin")

list(APPEND remoted_names "test_secure")
list(APPEND remoted_flags "-Wl,--wrap,fopen -Wl,--wrap,fread -Wl,--wrap,fwrite -Wl,--wrap,fclose -Wl,--wrap,remove \
                            -Wl,--wrap,sleep -Wl,--wrap,fgets -Wl,--wrap,fflush -Wl,--wrap,fseek \
                            -Wl,--wrap,stat -Wl,--wrap,getpid -Wl,--wrap=key_lock_write -Wl,--wrap=key_unlock -Wl,--wrap=time \
                            -Wl,--wrap,fgetpos -Wl,--wrap=fgetc -Wl,--wrap=OS_IsAllowedDynamicID -Wl,--wrap=_mwarn \
                            -Wl,--wrap=OS_DeleteSocket -Wl,--wrap=nb_close -Wl,--wrap=rem_setCounter -Wl,--wrap=key_lock_read \
                            -Wl,--wrap=rem_inc_tcp -Wl,--wrap=rem_dec_tcp -Wl,--wrap=close -Wl,--wrap=accept \
                            -Wl,--wrap=wnotify_add -Wl,--wrap,fcntl -Wl,--wrap,_merror -Wl,--wrap=nb_open -Wl,--wrap=recvfrom \
                            -Wl,--wrap=rem_msgpush -Wl,--wrap=rem_add_recv -Wl,--wrap=nb_recv -Wl,--wrap=nb_send \
                            -Wl,--wrap=rem_add_send ${DEBUG_OP_WRAPPERS}")

list(APPEND remoted_names "test_netbuffer")
list(APPEND remoted_flags "-Wl,--wrap,_merror -Wl,--wrap,_mwarn -Wl,--wrap,_mdebug1 -Wl,--wrap,wnet_order -Wl,--wrap,wnotify_modify \
                            -Wl,--wrap,bqueue_push -Wl,--wrap,bqueue_peek -Wl,--wrap,bqueue_drop -Wl,--wrap,bqueue_clear -Wl,--wrap,sleep \
                            -Wl,--wrap,send -Wl,--wrap,pthread_mutex_lock -Wl,--wrap,pthread_mutex_unlock -Wl,--wrap,fcntl -Wl,--wrap,getpid \
                            -Wl,--wrap,bqueue_used")

list(APPEND remoted_names "test_sendmsg")
list(APPEND remoted_flags "-Wl,--wrap,_merror -Wl,--wrap,_mdebug1 -Wl,--wrap,OS_IsAllowedID -Wl,--wrap,pthread_mutex_lock -Wl,--wrap,pthread_mutex_unlock \
                            -Wl,--wrap,pthread_rwlock_rdlock -Wl,--wrap,pthread_rwlock_unlock -Wl,--wrap,CreateSecMSG -Wl,--wrap,nb_queue -Wl,--wrap,time")

list(APPEND remoted_names "test_remote-config")
list(APPEND remoted_flags "${DEBUG_OP_WRAPPERS}")
list(APPEND remoted_names "test_syslogtcp")
list(APPEND remoted_flags "-W")

list(LENGTH remoted_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET remoted_names ${counter} remoted_test_name)
    list(GET remoted_flags ${counter} remoted_test_flags)

    add_executable(${remoted_test_name} ${remoted_test_name}.c)

    target_link_libraries(
        ${remoted_test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        REMOTED_O
        ${TEST_DEPS}
    )

    if(NOT remoted_test_flags STREQUAL " ")
        target_link_libraries(
            ${remoted_test_name}
            ${remoted_test_flags}
        )
    endif()
    add_test(NAME ${remoted_test_name} COMMAND ${remoted_test_name})
endforeach()
