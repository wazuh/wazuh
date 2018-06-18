# libcap-ng.m4 - Checks for the libcap-ng support
# 	Copyright (c) 2009 Steve Grubb sgrubb@redhat.com
#
AC_DEFUN([LIBCAP_NG_PATH],
[
  AC_ARG_WITH(libcap-ng,
    [  --with-libcap-ng=[auto/yes/no]  Add Libcap-ng support [default=auto]],,
    with_libcap_ng=auto)

  # Check for Libcap-ng API
  #
  # libcap-ng detection

  if test x$with_libcap_ng = xno ; then
      have_libcap_ng=no;
  else
      # Start by checking for header file
      AC_CHECK_HEADER(cap-ng.h, capng_headers=yes, capng_headers=no)

      # See if we have libcap-ng library
      AC_CHECK_LIB(cap-ng, capng_clear,
	         CAPNG_LDADD=-lcap-ng,)

      # Check results are usable
      if test x$with_libcap_ng = xyes -a x$CAPNG_LDADD = x ; then
         AC_MSG_ERROR(libcap-ng support was requested and the library was not found)
      fi
      if test x$CAPNG_LDADD != x -a $capng_headers = no ; then
         AC_MSG_ERROR(libcap-ng libraries found but headers are missing)
      fi
  fi
  AC_SUBST(CAPNG_LDADD)
  AC_MSG_CHECKING(whether to use libcap-ng)
  if test x$CAPNG_LDADD != x ; then
      AC_DEFINE(HAVE_LIBCAP_NG,1,[libcap-ng support])
      AC_MSG_RESULT(yes)
  else
      AC_MSG_RESULT(no)
  fi
])
