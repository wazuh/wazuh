install(FILES
       argv.h rpmbase64.h rpmcrypto.h rpmfileutil.h rpmio.h
       rpmkeyring.h rpmlog.h rpmmacro.h rpmpgp.h rpmsq.h rpmstring.h
       rpmstrpool.h rpmsw.h rpmurl.h rpmutil.h rpmver.h

        header.h rpmarchive.h rpmcallback.h rpmcli.h
        rpmdb.h rpmds.h rpmfi.h rpmfiles.h rpmlib.h
        rpmprob.h rpmps.h rpmtag.h rpmtd.h rpmte.h rpmte.h rpmts.h
        rpmtypes.h rpmplugin.h

	rpmbuild.h rpmspec.h rpmfc.h

	rpmsign.h
	DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/rpm
)
