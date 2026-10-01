add_library(librpmio SHARED)

target_sources(librpmio PRIVATE
	argv.c base64.c digest.c expression.c macro.c rpmhook.h rpmhook.c
	rpmio.c rpmlog.c rpmmalloc.c rgetopt.c rpmpgp.c rpmpgpval.h
	rpmsq.c rpmsw.c url.c rpmio_internal.h rpmvercmp.c
	rpmver.c rpmstring.c rpmfileutil.c rpmglob.c rpmkeyring.c
	rpmstrpool.c rpmmacro_internal.h rpmlua.c rpmlua.h lposix.c
)
target_compile_definitions(librpmio PRIVATE RPM_CONFIGDIR="${RPM_CONFIGDIR}")
target_include_directories(librpmio 
    PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}
	${Intl_INCLUDE_DIRS}
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

if (EXISTS ${CMAKE_SOURCE_DIR}/rpmio/rpmpgp_legacy/CMakeLists.txt)
	add_subdirectory(rpmpgp_legacy)
endif()

if (WITH_SEQUOIA)
	pkg_check_modules(RPMSEQUOIA REQUIRED IMPORTED_TARGET rpm-sequoia>=1.4.0)
	target_sources(librpmio PRIVATE rpmpgp_sequoia.c)
	target_link_libraries(librpmio PRIVATE PkgConfig::RPMSEQUOIA)
else()
	if (WITH_LEGACY_OPENPGP)
		target_link_libraries(librpmio PRIVATE rpmpgp_legacy)
	else()
		target_sources(librpmio PRIVATE rpmpgp_dummy.c)
	endif()
	if (WITH_OPENSSL)
		find_package(OpenSSL 1.0.2 REQUIRED)
		target_sources(librpmio PRIVATE digest_openssl.c)
		target_link_libraries(librpmio PRIVATE OpenSSL::Crypto)
	else()
		pkg_check_modules(LIBGCRYPT REQUIRED IMPORTED_TARGET libgcrypt)
		target_sources(librpmio PRIVATE digest_libgcrypt.c)
		target_link_libraries(librpmio PRIVATE PkgConfig::LIBGCRYPT)
	endif()
endif()

if (WITH_CXX)
set (cxx_sources
	argv.c base64.c digest.c expression.c lposix.c macro.c
	digest_libgcrypt.c digest_openssl.c
	rgetopt.c rpmfileutil.c rpmglob.c rpmhook.c rpmio.c
	rpmkeyring.c rpmlog.c rpmlua.c rpmpgp.c rpm_sequoia.c rpmsq.c
	rpmsw.c rpmstring.c rpmstrpool.c
	rpmver.c rpmvercmp.c url.c
)
set_source_files_properties(${cxx_sources} PROPERTIES LANGUAGE CXX)
endif()

set_target_properties(librpmio PROPERTIES
	VERSION ${RPM_LIBVERSION}
	SOVERSION ${RPM_SOVERSION}
)
target_link_libraries(librpmio PRIVATE
	PkgConfig::POPT
	LUA::LUA
	ZLIB::ZLIB
	${Intl_LIBRARIES}
)

if (ZSTD_FOUND)
	target_link_libraries(librpmio PRIVATE PkgConfig::ZSTD)
endif()
if (LIBLZMA_FOUND)
	target_link_libraries(librpmio PRIVATE PkgConfig::LIBLZMA)
endif()
if (BZIP2_FOUND)
	target_link_libraries(librpmio PRIVATE BZip2::BZip2)
endif()
if (OpenMP_C_FOUND)
        target_link_libraries(librpmio PRIVATE OpenMP::OpenMP_C)
endif()

install(TARGETS librpmio EXPORT rpm-targets)
