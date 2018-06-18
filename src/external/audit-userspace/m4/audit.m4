# audit.m4 - Checks for the libaudit support
#       Copyright (c) 2015 Steve Grubb sgrubb@redhat.com
#
AC_DEFUN([AUDIT_PATH],
[
  AC_ARG_WITH(audit,
    [  --with-audit=[auto/yes/no]  Add audit support [default=auto]],,
    with_audit=auto)

  # Check for libaudit API
  #
  # libaudit detection

  if test "x$with_audit" = xno ; then
      have_audit=no;
  else
      # Start by checking for header file
      AC_CHECK_HEADER(audit.h, audit_headers=yes, audit_headers=no)

      # See if we have libaudit library
      AC_CHECK_LIB(audit, audit_open,
                 AUDIT_LDADD=-laudit,)

      # Check that results are usable
      if test "x$with_audit" = xyes -a "x$AUDIT_LDADD" = x ; then
         AC_MSG_ERROR(audit support was requested and the library was not found)
      fi
      if test "x$AUDIT_LDADD" != x -a "$audit_headers" = no ; then
         AC_MSG_ERROR(audit libraries found but headers are missing)
      fi
  fi
  AC_SUBST(AUDIT_LDADD)
  AC_MSG_CHECKING(whether to use audit)
  if test "x$AUDIT_LDADD" != x ; then
      AC_DEFINE(HAVE_AUDIT,1,[audit support])
      AC_MSG_RESULT(yes)
  else
      AC_MSG_RESULT(no)
  fi
])
