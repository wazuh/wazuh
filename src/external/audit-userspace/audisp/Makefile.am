# Makefile.am-- 
# Copyright 2007,2011,2015-16 Red Hat Inc., Durham, North Carolina.
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
#   Steve Grubb <sgrubb@redhat.com>
#

SUBDIRS = plugins 
CONFIG_CLEAN_FILES = *.rej *.orig
AUTOMAKE_OPTIONS = no-dependencies
AM_CPPFLAGS = -I${top_srcdir} -I${top_srcdir}/lib
sbin_PROGRAMS = audispd
noinst_HEADERS = audispd-config.h audispd-pconfig.h audispd-llist.h \
	queue.h audispd-builtins.h
LIBS = -L${top_builddir}/lib -laudit 
LDADD = -lpthread
AM_CFLAGS = -D_REENTRANT 

audispd_SOURCES = audispd.c audispd-config.c audispd-pconfig.c \
	audispd-llist.c queue.c audispd-builtins.c
audispd_CFLAGS = -fPIE -DPIE -g -D_GNU_SOURCE
audispd_LDFLAGS = -pie -Wl,-z,relro -Wl,-z,now

install-exec-hook:
	chmod 0750 $(DESTDIR)$(sbindir)/audispd
