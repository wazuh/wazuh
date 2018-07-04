#
# Makefile.am --
# Copyright (c) 2011 IBM Corp.
# Copyright (C) 2015 Red Hat, Inc.
# All Rights Reserved.
#
# This software may be freely redistributed and/or modified under the
# terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not, write to the
# Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor 
# Boston, MA 02110-1335, USA.
#
# Authors:
#   Marcelo Henrique Cerri <mhcerri@br.ibm.com>
#
 
CONFIG_CLEAN_FILES = *.loT *.rej *.orig
AUTOMAKE_OPTIONS = no-dependencies
EXTRA_DIST = $(man_MANS)
AM_CPPFLAGS = -I${top_srcdir} \
		   -I${top_srcdir}/lib \
		   -I${top_srcdir}/auparse \
		   -I${top_srcdir}/src
LIBS = -L${top_builddir}/auparse -lauparse
AM_CFLAGS = -D_GNU_SOURCE
bin_PROGRAMS = auvirt
noinst_HEADERS = auvirt-list.h
man_MANS = auvirt.8

auvirt_SOURCES = auvirt.c \
		 auvirt-list.c \
		 ${top_srcdir}/src/ausearch-time.c
