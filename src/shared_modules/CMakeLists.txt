add_subdirectory(dbsync)
add_subdirectory(rsync)

if(UNIT_TEST)
    add_subdirectory(utils/tests)
endif(UNIT_TEST)
