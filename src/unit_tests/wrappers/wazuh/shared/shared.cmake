set(HASH_OP_WRAPPERS "-Wl,--wrap,OSHash_Add \
                      -Wl,--wrap,OSHash_Add_ex \
                      -Wl,--wrap,OSHash_Begin \
                      -Wl,--wrap,OSHash_Begin_ex \
                      -Wl,--wrap,OSHash_Clean \
                      -Wl,--wrap,OSHash_Create \
                      -Wl,--wrap,OSHash_Delete_ex \
                      -Wl,--wrap,OSHash_Delete \
                      -Wl,--wrap,OSHash_Get \
                      -Wl,--wrap,OSHash_Get_ex \
                      -Wl,--wrap,OSHash_Get_ex_dup \
                      -Wl,--wrap,OSHash_Next \
                      -Wl,--wrap,OSHash_SetFreeDataPointer \
                      -Wl,--wrap,OSHash_setSize \
                      -Wl,--wrap,OSHash_Update_ex \
                      -Wl,--wrap,OSHash_Update \
                      -Wl,--wrap,OSHash_Get_Elem_ex")


set(DEBUG_OP_WRAPPERS "-Wl,--wrap,_mdebug1 \
                       -Wl,--wrap,_mdebug2 \
                       -Wl,--wrap,_merror \
                       -Wl,--wrap,_merror_exit \
                       -Wl,--wrap,_mferror \
                       -Wl,--wrap,_minfo \
                       -Wl,--wrap,_mtdebug1 \
                       -Wl,--wrap,_mtdebug2 \
                       -Wl,--wrap,_mterror \
                       -Wl,--wrap,_mterror_exit \
                       -Wl,--wrap,_mtinfo \
                       -Wl,--wrap,_mtwarn \
                       -Wl,--wrap,_mwarn")

set(STDIO_OP_WRAPPERS "-Wl,--wrap,fclose \
                       -Wl,--wrap,fflush \
                       -Wl,--wrap,fgets \
                       -Wl,--wrap,fgetpos \
                       -Wl,--wrap,fopen \
                       -Wl,--wrap,fread \
                       -Wl,--wrap,fseek \
                       -Wl,--wrap,fwrite \
                       -Wl,--wrap,remove \
                       -Wl,--wrap,fgetc")
