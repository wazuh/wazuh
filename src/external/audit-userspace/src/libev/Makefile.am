# Makefile.am-- 
# Copyright 2008,2011-12 Red Hat Inc., Durham, North Carolina.
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
VERSION_INFO = 4:0:0
EXTRA_DIST = README ev_epoll.c ev_poll.c ev_select.c libev.m4
AM_CFLAGS = -fPIC -DPIC -g -fno-strict-aliasing ${DEBUG}

noinst_HEADERS = ev.h ev_vars.h ev_wrap.h event.h
noinst_LIBRARIES = libev.a

libev_a_SOURCES = ev.c event.c
