dnl
define([AC_INIT_NOTICE],
[### Generated automatically using autoconf version] AC_ACVERSION [
### Copyright 2005-18 Steve Grubb <sgrubb@redhat.com>
###
### Permission is hereby granted, free of charge, to any person obtaining a
### copy of this software and associated documentation files (the "Software"),
### to deal in the Software without restriction, including without limitation
### the rights to use, copy, modify, merge, publish, distribute, sublicense,
### and/or sell copies of the Software, and to permit persons to whom the
### Software is furnished to do so, subject to the following conditions:
###
### The above copyright notice and this permission notice shall be included
### in all copies or substantial portions of the Software.
###
### THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
### IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
### FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
### THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
### OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
### ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
### OTHER DEALINGS IN THE SOFTWARE.
###
### For usage, run `./configure --help'
### For more detailed information on installation, read the file `INSTALL'.
###
### If configuration succeeds, status is in the file `config.status'.
### A log of configuration tests is in `config.log'.
])

AC_REVISION($Revision: 1.3 $)dnl
AC_INIT(audit,3.0)
AC_PREREQ(2.12)dnl
AM_CONFIG_HEADER(config.h)

echo Configuring auditd $VERSION

AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE
AM_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)
OLDLIBS="$LIBS"
m4_include([src/libev/libev.m4])
libev_LIBS="$LIBS"
LIBS="$OLDLIBS"

echo .
echo Checking for programs

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_AWK
AX_PROG_CC_FOR_BUILD

echo .
echo Checking for header files
AC_HEADER_STDC
AC_HEADER_TIME

AC_C_CONST
AC_C_INLINE
AC_CHECK_SIZEOF([unsigned int])
AC_CHECK_SIZEOF([unsigned long])
AM_PROG_CC_C_O
AC_CHECK_DECLS([AUDIT_FEATURE_VERSION], [], [], [[#include <linux/audit.h>]])
AC_CHECK_MEMBERS([struct audit_status.feature_bitmap], [], [], [[#include <linux/audit.h>]])
AC_CHECK_DECLS([AUDIT_VERSION_BACKLOG_WAIT_TIME], [], [], [[#include <linux/audit.h>]])
AC_CHECK_DECLS([AUDIT_STATUS_BACKLOG_WAIT_TIME], [], [], [[#include <linux/audit.h>]])
AC_CHECK_DECLS([ADDR_NO_RANDOMIZE],,, [#include <sys/personality.h>])
dnl; posix_fallocate is used in audisp-remote
AC_CHECK_FUNCS([posix_fallocate])
dnl; signalfd is needed for libev
AC_CHECK_FUNC([signalfd], [], [ AC_MSG_ERROR([The signalfd system call is necessary for auditd]) ])

ALLWARNS=""
ALLDEBUG="-g"
OPT="-O"
if test x"$GCC" = x"yes"; then
  OPT="-O2 -pipe"
  case "$target" in
    *linux*)
             ALLWARNS="-W -Wall -Wundef -Wpointer-arith -Wcast-align \
-Wwrite-strings -Waggregate-return -Wstrict-prototypes \
-Wmissing-prototypes -Wmissing-declarations -Wredundant-decls \
-Wnested-externs -Winline -Wfloat-equal -Wchar-subscripts"
             ;;
    esac
fi

AC_MSG_CHECKING(whether to create python bindings)
AC_ARG_WITH(python,
AS_HELP_STRING([--with-python],[enable building python bindings]),
use_python=$withval,
use_python=auto)
if test "x$use_python" = xno ; then
	python_found="no"
	AC_MSG_RESULT(no)
else
AC_MSG_RESULT(testing)
AM_PATH_PYTHON
PYINCLUDEDIR=`python${am_cv_python_version} -c "from distutils import sysconfig; print(sysconfig.get_config_var('INCLUDEPY'))"`
if test -f ${PYINCLUDEDIR}/Python.h ; then
	python_found="yes"
	AC_SUBST(PYINCLUDEDIR)
	pybind_dir="python"
	AC_SUBST(pybind_dir)
	AC_MSG_NOTICE(Python bindings will be built)
else
	python_found="no"
	if test "x$use_python" = xyes ; then
		AC_MSG_ERROR([Python explicitly requested and python headers were not found])
	else
		AC_MSG_WARN("Python headers not found - python bindings will not be made")
	fi
fi
fi
AM_CONDITIONAL(HAVE_PYTHON, test ${python_found} = "yes")

withval=""
AC_MSG_CHECKING(whether to create python3 bindings)
AC_ARG_WITH(python3,
AS_HELP_STRING([--with-python3],[enable building python3 bindings]),
use_python3=$withval,
use_python3=auto)
if test "x$use_python3" = xno ; then
	AC_MSG_RESULT(no)
else
	AC_MSG_RESULT(investigating)
	AC_PATH_PROG([use_python3], [python3-config], [no])
	if test "x$use_python3" = xno ; then
		if test "x$withval" = xyes ; then
			echo "Python3 bindings were selected but python3-config was not found."
			echo "Please ensure that it's installed or pass --without-python3 to ./configure"
			exit 1
		fi
		echo "Python3 bindings will NOT be built"
	else
	echo "Python3 bindings WILL be built"
	use_python3=yes
	AC_PATH_PROG([PYTHON3], [python3], [no])
	if test "x$PYTHON3" = "xno" ; then
		echo "The python3 program was not found in the search path. Please ensure"
		echo "that it is installed and its directory is included in the search path or"
		echo "pass --without-python3 to ./configure."
		exit 1
	fi
	PYTHON3_CFLAGS=`python3-config --cflags 2> /dev/null`
	PYTHON3_LIBS=`python3-config --libs 2> /dev/null`
	PYTHON3_INCLUDES=`python3-config --includes 2> /dev/null`
	AC_SUBST([PYTHON3_PREFIX], ['${prefix}'])
	AC_SUBST([PYTHON3_EXEC_PREFIX], ['${exec_prefix}'])
	PYTHON3_DIR=`$PYTHON3 -c "import distutils.sysconfig; \
	print(distutils.sysconfig.get_python_lib(0,0,prefix='$PYTHON3_PREFIX'))"`
	PYTHON3_EXECDIR=`$PYTHON3 -c "import distutils.sysconfig; \
	print(distutils.sysconfig.get_python_lib(1,0,prefix='$PYTHON3_EXEC_PREFIX'))"`
	AC_SUBST(PYTHON3_CFLAGS)
	AC_SUBST(PYTHON3_LIBS)
	AC_SUBST(PYTHON3_INCLUDES)
	AC_SUBST(python3dir, $PYTHON3_DIR)
	AC_SUBST(py3execdir, $PYTHON3_EXECDIR)
	fi
fi
AM_CONDITIONAL(USE_PYTHON3, test ${use_python3} = "yes")

withval=""
AC_MSG_CHECKING(whether to create Go language bindings)
AC_ARG_WITH(golang,
AS_HELP_STRING([--with-golang],[enable building golang bindings]),
use_golang=$withval,
use_golang=auto)
if test "x$use_golang" = xno ; then
    golang_found="no"
    AC_MSG_RESULT(no)
else
    AC_MSG_RESULT(testing)
    AC_CHECK_PROG([GOLANG],[go],[go],[no])
    AS_IF([test "x$GOLANG" != "xno"],[
	AC_MSG_NOTICE(Go bindings will be built)
        golang_found="yes"

        # Substitute some golang environment.
        GOROOT=`$GOLANG env GOROOT`
        AC_SUBST([GOROOT])
    ], [
	if test "x$use_golang" = xyes ; then
		AC_MSG_ERROR([Go language explicitly requested and program not found])
	else
		AC_MSG_WARN("Go not found - go bindings will not be made")
	fi
    ])
fi
AM_CONDITIONAL(HAVE_GOLANG, test ${golang_found} = "yes")

#auditd listener
AC_MSG_CHECKING(whether to include auditd network listener support)
AC_ARG_ENABLE(listener,
	      [AS_HELP_STRING([--disable-listener],
			      [Disable auditd network listener support])],
	      enable_listener=$enableval,
	      enable_listener=yes)
if test "x$enable_listener" != "xno"; then
	AC_DEFINE(USE_LISTENER, 1,
		  [Define if you want to use the auditd network listener.])
fi
AM_CONDITIONAL(ENABLE_LISTENER, test "x$enable_listener" != "xno")
AC_MSG_RESULT($enable_listener)

#audisp zos-remote plugin
AC_MSG_CHECKING(whether to include audisp ZOS remote plugin)
AC_ARG_ENABLE(zos-remote,
	      [AS_HELP_STRING([--disable-zos-remote],
			      [Disable audisp ZOS remote plugin])],
	      enable_zos_remote=$enableval,
	      enable_zos_remote=yes)
AM_CONDITIONAL(ENABLE_ZOS_REMOTE, test "x$enable_zos_remote" != "xno")
AC_MSG_RESULT($enable_zos_remote)

#gssapi
AC_ARG_ENABLE(gssapi_krb5,
	[AS_HELP_STRING([--enable-gssapi-krb5],[Enable GSSAPI Kerberos 5 support @<:@default=no@:>@])],
        [case "${enableval}" in
         yes) want_gssapi_krb5="yes" ;;
          no) want_gssapi_krb5="no" ;;
           *) AC_MSG_ERROR(bad value ${enableval} for --enable-gssapi-krb5) ;;
         esac],
	[want_gssapi_krb5="no"]
)
if test $want_gssapi_krb5 = yes; then
	AC_CHECK_LIB(gssapi_krb5, gss_acquire_cred, [
		AC_CHECK_HEADER(gssapi/gssapi.h, [
			AC_DEFINE(USE_GSSAPI,,
				  Define if you want to use GSSAPI)
			gss_libs="-lgssapi_krb5 -lkrb5"
			AC_SUBST(gss_libs)
		])
	])
fi
AM_CONDITIONAL(ENABLE_GSSAPI, test x$want_gssapi_krb5 = xyes)

#systemd
AC_ARG_ENABLE(systemd,
	[AS_HELP_STRING([--enable-systemd],[Enable systemd init scripts @<:@default=no@:>@])],
        [case "${enableval}" in
         yes) want_systemd="yes" ;;
          no) want_systemd="no" ;;
           *) AC_MSG_ERROR(bad value ${enableval} for --enable-systemd) ;;
         esac],
	[want_systemd="no"]
)
AM_CONDITIONAL(ENABLE_SYSTEMD, test x$want_systemd = xyes)

# linux/fanotify.h
AC_CHECK_HEADER(linux/fanotify.h, [ AC_DEFINE(USE_FANOTIFY, [],
	[Defined when fanotify headers are found]) ])

withval=""
ALLDEBUG="-g"
AC_ARG_WITH(debug,
[  --with-debug            turn on debugging [[default=no]]],
[
if test "x${withval}" = xyes; then
        DEBUG="$ALLDEBUG"
        OPT="-O"
        AM_CONDITIONAL(DEBUG, true)
else
        DEBUG="-DNDEBUG"
        AM_CONDITIONAL(DEBUG, false)
fi
],
[ DEBUG="-DNDEBUG"; AM_CONDITIONAL(DEBUG, false) ])

withval=""
AC_ARG_WITH(warn,
[  --with-warn             turn on warnings [[default=yes]]],
[
if test "x${withval}" = xyes; then
        WARNS="$ALLWARNS"
else
        WARNS=""
fi
],WARNS="$ALLWARNS")

withval=""
AC_MSG_CHECKING(whether to include alpha processor support)
AC_ARG_WITH(alpha,
AS_HELP_STRING([--with-alpha],[enable Alpha processor support]),
use_alpha=$withval,
use_alpha=no)
if test x$use_alpha != xno ; then
      AC_DEFINE(WITH_ALPHA,1,[Define if you want to enable Alpha processor support.])
fi
AM_CONDITIONAL(USE_ALPHA, test x$use_alpha = xyes)
AC_MSG_RESULT($use_alpha)

withval=""
AC_MSG_CHECKING(whether to include arm eabi processor support)
AC_ARG_WITH(arm,
AS_HELP_STRING([--with-arm],[enable Arm eabi processor support]),
use_arm=$withval,
use_arm=no)
if test x$use_arm != xno ; then
      AC_DEFINE(WITH_ARM,1,[Define if you want to enable Arm eabi processor support.])
fi
AM_CONDITIONAL(USE_ARM, test x$use_arm = xyes)
AC_MSG_RESULT($use_arm)

withval=""
AC_MSG_CHECKING(whether to include aarch64 processor support)
AC_ARG_WITH(aarch64,
AS_HELP_STRING([--with-aarch64],[enable Aarch64 processor support]),
use_aarch64=$withval,
use_aarch64=no)
if test x$use_aarch64 != xno ; then
      AC_DEFINE(WITH_AARCH64,1,[Define if you want to enable Aarch64 processor support.])
fi
AM_CONDITIONAL(USE_AARCH64, test x$use_aarch64 = xyes)
AC_MSG_RESULT($use_aarch64)

withval=""
AC_MSG_CHECKING(whether to use apparmor)
AC_ARG_WITH(apparmor,
AS_HELP_STRING([--with-apparmor],[enable AppArmor events]),
use_apparmor=$withval,
use_apparmor=no)
if test x$use_apparmor != xno ; then
      AC_DEFINE(WITH_APPARMOR,1,[Define if you want to enable AppArmor events.])
fi
AC_MSG_RESULT($use_apparmor)

withval=""
AC_MSG_CHECKING(whether to use libwrap)
AC_ARG_WITH(libwrap,
[  --with-libwrap[=PATH]   Compile in libwrap (tcp_wrappers) support.],
[ case "$withval" in
	no)
		AC_MSG_RESULT(no)
		;;
	yes)
		AC_MSG_RESULT(yes)
		AC_CHECK_HEADER(tcpd.h, [],
			AC_MSG_ERROR([Could not find libwrap headers]),)
		AC_CHECK_LIB(wrap, request_init, [ LIBWRAP_LIBS="-lwrap" ])
		AC_CHECK_LIB(nsl, yp_get_default_domain, [
			LIBWRAP_LIBS="$LIBWRAP_LIBS -lnsl" ])
		;;
	*)
		AC_MSG_RESULT(yes)
		if test -d "$withval"; then
			LIBWRAP_LIBS="-L$withval -lwrap"
		else
			LIBWRAP_LIBS="$withval"
		fi
		AC_CHECK_HEADER(tcpd.h, [],
			AC_MSG_ERROR([Could not find libwrap headers]))
		AC_CHECK_LIB(wrap, request_init, [])
		AC_CHECK_LIB(nsl, yp_get_default_domain, [
			LIBWRAP_LIBS="$LIBWRAP_LIBS -lnsl" ])
		OLDLIBS="$LIBS"
		LIBS="$LIBWRAP_LIBS $LIBS"
		AC_TRY_LINK([ int allow_severity; int deny_severity; ],
			[ hosts_access(); ], [],
			[ AC_MSG_ERROR(Could not find the $withval library.  You must first install tcp_wrappers.) ])
		LIBS="$OLDLIBS"
		;;
	esac ],
	AC_MSG_RESULT(no)
)
if test x"$LIBWRAP_LIBS" != "x"; then
	AC_DEFINE_UNQUOTED(HAVE_LIBWRAP, [], Define if tcp_wrappers support is enabled )
fi

# See if we want to support lower capabilities for plugins
LIBCAP_NG_PATH

AC_SUBST(DEBUG)
AC_SUBST(LIBWRAP_LIBS)
#AC_SUBST(libev_LIBS)
AC_SUBST(LIBPRELUDE_CFLAGS)
AC_SUBST(LIBPRELUDE_LDFLAGS)

AC_OUTPUT(Makefile lib/Makefile lib/audit.pc lib/test/Makefile auparse/Makefile auparse/test/Makefile auparse/auparse.pc src/Makefile src/libev/Makefile src/test/Makefile docs/Makefile rules/Makefile init.d/Makefile audisp/Makefile audisp/plugins/Makefile audisp/plugins/builtins/Makefile audisp/plugins/remote/Makefile audisp/plugins/zos-remote/Makefile bindings/Makefile bindings/python/Makefile bindings/python/python2/Makefile bindings/python/python3/Makefile bindings/golang/Makefile bindings/swig/Makefile bindings/swig/src/Makefile bindings/swig/python/Makefile bindings/swig/python3/Makefile tools/Makefile tools/aulast/Makefile tools/aulastlog/Makefile tools/ausyscall/Makefile tools/auvirt/Makefile m4/Makefile)

echo .
echo "

  Auditd Version:         $VERSION
  Target:                 $target
  Installation prefix:    $prefix
  Compiler:               $CC
  Compiler flags:
`echo $CFLAGS | fmt -w 50 | sed 's,^,                          ,'`
"
