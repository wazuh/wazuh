add_library(librpmbuild SHARED)
set_target_properties(librpmbuild PROPERTIES
	VERSION ${RPM_LIBVERSION}
	SOVERSION ${RPM_SOVERSION}
)
target_sources(librpmbuild PRIVATE
	build.c files.c misc.c pack.c
	parseSimpleScript.c parseChangelog.c parseDescription.c
	parseFiles.c parsePreamble.c parsePrep.c parseReqs.c parseScript.c
	parseSpec.c parseList.c reqprov.c rpmfc.c spec.c
	parsePolicies.c policies.c
	rpmbuild_internal.h rpmbuild_misc.h
	speclua.c
)

target_include_directories(librpmbuild
    PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}/rpmio
	${CMAKE_SOURCE_DIR}/lib
	${Intl_INCLUDE_DIRS}
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_link_libraries(librpmbuild PUBLIC librpmio librpm)
target_link_libraries(librpmbuild PRIVATE
	libmisc
	PkgConfig::POPT
	LUA::LUA
	MAGIC::MAGIC
	${Intl_LIBRARIES}
)

if (LIBDW_FOUND)
	target_link_libraries(librpmbuild PRIVATE PkgConfig::LIBDW)
endif()

if (LIBELF_FOUND)
	target_link_libraries(librpmbuild PRIVATE PkgConfig::LIBELF)
endif()

if (Iconv_FOUND)
	target_link_libraries(librpmbuild PRIVATE Iconv::Iconv)
endif()

if(WITH_CAP)
	target_link_libraries(librpmbuild PRIVATE PkgConfig::LIBCAP)
endif()

if(OpenMP_C_FOUND)
	target_link_libraries(librpmbuild PRIVATE OpenMP::OpenMP_C)
endif()

if (WITH_CXX)
set (cxx_sources
	build.c files.c misc.c pack.c
	parseChangelog.c parseDescription.c parseFiles.c parseList.c
	parsePolicies.c parsePreamble.c parsePrep.c parseReqs.c
	parseScript.c parseSimpleScript.c parseSpec.c
	policies.c reqprov.c rpmfc.c
	spec.c speclua.c
)
set_source_files_properties(${cxx_sources} PROPERTIES LANGUAGE CXX)
if (OpenMP_C_FOUND)
	target_link_libraries(librpmbuild PRIVATE OpenMP::OpenMP_CXX)
endif()
endif()

install(TARGETS librpmbuild EXPORT rpm-targets)
