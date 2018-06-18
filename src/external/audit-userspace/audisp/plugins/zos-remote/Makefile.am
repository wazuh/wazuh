# Makefile.am--
# Copyright (C) 2007,2008 International Business Machines  Corp.
# Copyright (C) 2011, 2015 Red Hat., Durham, North Carolina.
# All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# Authors:
#   Klaus Heinrich Kiwi <klausk@br.ibm.com>
#

AM_CPPFLAGS = -I${top_srcdir} -I${top_srcdir}/lib -I${top_srcdir}/auparse
CONFIG_CLEAN_FILES = *.rej *.orig
AUTOMAKE_OPTIONS = no-dependencies
EXTRA_DIST = zos-remote.conf audispd-zos-remote.conf
LIBS = -L${top_builddir}/auparse -lauparse
LDADD = -lpthread -lldap -llber $(CAPNG_LDADD) 
dispatcher_confdir = $(sysconfdir)/audisp
plugin_confdir=$(dispatcher_confdir)/plugins.d
plugin_conf = zos-remote.conf
dispatcher_conf = audispd-zos-remote.conf
sbin_PROGRAMS = audispd-zos-remote

noinst_HEADERS = zos-remote-log.h zos-remote-ldap.h zos-remote-config.h \
	zos-remote-queue.h
audispd_zos_remote_SOURCES = zos-remote-plugin.c zos-remote-log.c \
	zos-remote-ldap.c zos-remote-config.c zos-remote-queue.c
audispd_zos_remote_CFLAGS = -W -Wall -Wundef -D_GNU_SOURCE -fPIE -DPIE
audispd_zos_remote_LDFLAGS = -pie -Wl,-z,relro -Wl,-z,now

install-data-hook:
	mkdir -p -m 0750 ${DESTDIR}${plugin_confdir}
	$(INSTALL_DATA) -D -m 640 ${srcdir}/$(plugin_conf) \
	    ${DESTDIR}${dispatcher_confdir}
	$(INSTALL_DATA) -D -m 640 ${srcdir}/$(dispatcher_conf) \
	    ${DESTDIR}${plugin_confdir}

uninstall-hook:
	rm ${DESTDIR}${plugin_confdir}/$(dispatcher_conf)
	rm ${DESTDIR}${dispatcher_confdir}/$(plugin_conf)
