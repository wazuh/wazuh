add_library(librpmsign SHARED)
set_target_properties(librpmsign PROPERTIES
	VERSION ${RPM_LIBVERSION}
	SOVERSION ${RPM_SOVERSION}
)
target_sources(librpmsign PRIVATE rpmgensig.c)

target_include_directories(librpmsign
    PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}/rpmio
	${CMAKE_SOURCE_DIR}/lib
	${Intl_INCLUDE_DIRS}
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_link_libraries(librpmsign PUBLIC librpmio librpm)
target_link_libraries(librpmsign PRIVATE PkgConfig::POPT ${Intl_LIBRARIES})
if (WITH_IMAEVM)
	target_sources(librpmsign PRIVATE rpmsignfiles.c)
	target_link_libraries(librpmsign PRIVATE IMA::IMA)
endif()
if (WITH_FSVERITY)
	target_sources(librpmsign PRIVATE rpmsignverity.c)
	target_link_libraries(librpmsign PRIVATE PkgConfig::FSVERITY)
endif()

if (WITH_CXX)
set (cxx_sources
	rpmgensig.c rpmsignfiles.c rpmsignverity.c
)
set_source_files_properties(${cxx_sources} PROPERTIES LANGUAGE CXX)
endif()

install(TARGETS librpmsign EXPORT rpm-targets)
