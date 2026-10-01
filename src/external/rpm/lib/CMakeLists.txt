add_library(librpm SHARED)
set_target_properties(librpm PROPERTIES
	VERSION ${RPM_LIBVERSION}
	SOVERSION ${RPM_SOVERSION}
)

target_compile_definitions(librpm PRIVATE
	LOCALEDIR="${CMAKE_INSTALL_FULL_LOCALEDIR}"
	LOCALSTATEDIR="${CMAKE_INSTALL_FULL_LOCALSTATEDIR}"
	SYSCONFDIR="${CMAKE_INSTALL_FULL_SYSCONFDIR}"
	LIBRPMALIAS_FILENAME="rpmpopt-${PROJECT_VERSION}"
	LIBRPMALIAS_EXECPATH="${CMAKE_INSTALL_FULL_BINDIR}"
)

target_include_directories(librpm
    PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}/rpmio
	${CMAKE_CURRENT_BINARY_DIR}
	${Intl_INCLUDE_DIRS}
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        # This is needed for rpmcli.h
        ${POPT_INCLUDE_DIRS}
)

target_sources(librpm PRIVATE
	backend/dbi.c backend/dbi.h backend/dummydb.c
	backend/dbiset.c backend/dbiset.h
	headerutil.c header.c headerfmt.c header_internal.h
	rpmdb.c rpmdb_internal.h
	fprint.c fprint.h tagname.c rpmtd.c tagtbl.inc
	cpio.c cpio.h depends.c order.c formats.c tagexts.c fsm.c fsm.h
	manifest.c manifest.h package.c
	poptALL.c poptI.c poptQV.c psm.c query.c
	rpmal.c rpmal.h rpmchecksig.c rpmds.c rpmds_internal.h
	rpmfi.c rpmfi_internal.h
	rpmgi.h rpmgi.c rpminstall.c rpmts_internal.h
	rpmlead.c rpmlead.h rpmps.c rpmprob.c rpmrc.c
	rpmte.c rpmte_internal.h rpmts.c rpmfs.h rpmfs.c
	signature.c signature.h transaction.c
	verify.c rpmlock.c rpmlock.h misc.h relocation.c
	rpmscript.h rpmscript.c
	rpmchroot.c rpmchroot.h
	rpmplugins.c rpmplugins.h rpmug.c rpmug.h
	rpmtriggers.h rpmtriggers.c rpmvs.c rpmvs.h
)

if(ENABLE_SQLITE)
	target_sources(librpm PRIVATE backend/sqlite.c)
	target_link_libraries(librpm PRIVATE PkgConfig::SQLITE)
endif()

if(ENABLE_NDB)
	target_sources(librpm PRIVATE
		backend/ndb/glue.c
		backend/ndb/rpmpkg.c backend/ndb/rpmpkg.h
		backend/ndb/rpmidx.c backend/ndb/rpmidx.h
		backend/ndb/rpmxdb.c backend/ndb/rpmxdb.h
	)
endif()

if (WITH_CXX)
# sources converted to c++ so far (avoid having to do everything at once)
set (cxx_sources
	cpio.c depends.c formats.c fprint.c fsm.c header.c
	headerfmt.c headerutil.c manifest.c order.c package.c
	poptALL.c poptI.c poptQV.c psm.c
	query.c relocation.c rpmal.c rpmchecksig.c rpmchroot.c
	rpmdb.c rpmds.c rpmfi.c rpmfs.c rpmgi.c rpminstall.c
	rpmlead.c rpmlock.c rpmplugins.c rpmprob.c rpmps.c
	rpmrc.c rpmscript.c rpmtd.c rpmte.c rpmtriggers.c
	rpmts.c rpmug.c rpmvs.c signature.c tagexts.c tagname.c
	transaction.c verify.c
	backend/dbi.c backend/dbiset.c backend/bdb_ro.c
	backend/dummydb.c backend/sqlite.c backend/ndb/glue.c
)
set_source_files_properties(${cxx_sources} PROPERTIES LANGUAGE CXX)
endif()

if(ENABLE_BDB_RO)
	target_sources(librpm PRIVATE backend/bdb_ro.c)
endif()

if(WITH_ACL)
	target_link_libraries(librpm PRIVATE PkgConfig::LIBACL)
endif()

if(WITH_CAP)
	target_link_libraries(librpm PRIVATE PkgConfig::LIBCAP)
endif()

add_custom_command(OUTPUT tagtbl.inc
	COMMAND AWK=${AWK} ${CMAKE_CURRENT_SOURCE_DIR}/gentagtbl.sh ${CMAKE_SOURCE_DIR}/include/rpm/rpmtag.h > tagtbl.inc
	DEPENDS ${CMAKE_SOURCE_DIR}/include/rpm/rpmtag.h gentagtbl.sh
)

target_link_libraries(librpm PUBLIC librpmio)
target_link_libraries(librpm PRIVATE PkgConfig::POPT LUA::LUA ${Intl_LIBRARIES})

install(TARGETS librpm EXPORT rpm-targets)
