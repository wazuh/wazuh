# Makefile.am --
# Copyright 2008-09,2015 Red Hat Inc., Durham, North Carolina.
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

CONFIG_CLEAN_FILES = *.rej *.orig
EXTRA_DIST = au-prelude.conf audisp-prelude.conf
AUTOMAKE_OPTIONS = no-dependencies
AM_CPPFLAGS = -I${top_srcdir} -I${top_srcdir}/lib -I${top_srcdir}/auparse
LIBS = -L${top_builddir}/auparse/.libs -lauparse -lprelude 
LDADD = -lpthread $(CAPNG_LDADD) 
prog_confdir = $(sysconfdir)/audisp
prog_conf = audisp-prelude.conf
plugin_confdir=$(prog_confdir)/plugins.d
plugin_conf = au-prelude.conf
sbin_PROGRAMS = audisp-prelude
noinst_HEADERS = prelude-config.h audisp-int.h
dist_man_MANS = audisp-prelude.8 audisp-prelude.conf.5

audisp_prelude_SOURCES = audisp-prelude.c prelude-config.c audisp-int.c
audisp_prelude_CFLAGS = -fPIE -DPIE -g -D_REENTRANT -D_GNU_SOURCE -Wundef \
	@LIBPRELUDE_CFLAGS@
audisp_prelude_LDFLAGS = -pie -Wl,-z,relro -Wl,-z,now @LIBPRELUDE_LDFLAGS@

install-data-hook:
	mkdir -p -m 0750 ${DESTDIR}${plugin_confdir}
	$(INSTALL_DATA) -D -m 640 ${srcdir}/$(plugin_conf) ${DESTDIR}${plugin_confdir}
	$(INSTALL_DATA) -D -m 640 ${srcdir}/$(prog_conf) ${DESTDIR}${prog_confdir}

uninstall-hook:
	rm ${DESTDIR}${plugin_confdir}/$(plugin_conf)
	rm ${DESTDIR}${prog_confdir}/$(prog_conf)

