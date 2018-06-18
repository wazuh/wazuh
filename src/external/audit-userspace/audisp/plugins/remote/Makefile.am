# Makefile.am --
# Copyright 2008-2009,2011,2015 Red Hat Inc., Durham, North Carolina.
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
EXTRA_DIST = au-remote.conf audisp-remote.conf notes.txt $(man_MANS)
AM_CPPFLAGS = -I${top_srcdir} -I${top_srcdir}/lib 
prog_confdir = $(sysconfdir)/audisp
prog_conf = audisp-remote.conf
plugin_confdir=$(prog_confdir)/plugins.d
plugin_conf = au-remote.conf
sbin_PROGRAMS = audisp-remote
noinst_HEADERS = remote-config.h queue.h remote-fgets.h
man_MANS = audisp-remote.8 audisp-remote.conf.5
check_PROGRAMS = test-queue
TESTS = $(check_PROGRAMS)

audisp_remote_SOURCES = audisp-remote.c remote-config.c queue.c remote-fgets.c
audisp_remote_CFLAGS = -fPIE -DPIE -g -D_REENTRANT -D_GNU_SOURCE -Wundef
audisp_remote_LDFLAGS = -pie -Wl,-z,relro -Wl,-z,now $(gss_libs)
audisp_remote_LDADD = $(CAPNG_LDADD)

test_queue_SOURCES = queue.c test-queue.c

install-data-hook:
	mkdir -p -m 0750 ${DESTDIR}${plugin_confdir}
	$(INSTALL_DATA) -D -m 640 ${srcdir}/$(plugin_conf) ${DESTDIR}${plugin_confdir}
	$(INSTALL_DATA) -D -m 640 ${srcdir}/$(prog_conf) ${DESTDIR}${prog_confdir}

uninstall-hook:
	rm ${DESTDIR}${plugin_confdir}/$(plugin_conf)
	rm ${DESTDIR}${prog_confdir}/$(prog_conf)

