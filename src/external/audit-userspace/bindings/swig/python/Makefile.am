# Makefile.am -- 
# Copyright 2005,2007,2015 Red Hat Inc., Durham, North Carolina.
# All Rights Reserved.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
# 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
# 
# Authors:
#   Steve Grubb <sgrubb@redhat.com>
#
CONFIG_CLEAN_FILES = *.loT *.rej *.orig
AM_CFLAGS = -fPIC -DPIC -fno-strict-aliasing
AM_CPPFLAGS = -I. -I$(top_builddir) -I${top_srcdir}/lib -I@PYINCLUDEDIR@
SWIG_FLAGS = -python
SWIG_INCLUDES = -I. -I$(top_builddir) -I${top_srcdir}/lib -I@PYINCLUDEDIR@
pyexec_PYTHON = audit.py
pyexec_LTLIBRARIES = _audit.la
pyexec_SOLIBRARIES = _audit.so
_audit_la_CFLAGS = -shared
_audit_la_LDFLAGS = -module -avoid-version -Wl,-z,relro
_audit_la_HEADERS: $(top_builddir)/config.h 
_audit_la_DEPENDENCIES =${top_srcdir}/lib/libaudit.h ${top_builddir}/lib/libaudit.la
_audit_la_LIBADD = $(top_builddir)/lib/libaudit.la
nodist__audit_la_SOURCES  = audit_wrap.c
audit.py audit_wrap.c: ${srcdir}/../src/auditswig.i 
	swig -o audit_wrap.c ${SWIG_FLAGS} ${SWIG_INCLUDES} ${srcdir}/../src/auditswig.i 

CLEANFILES = audit.py* audit_wrap.c *~

