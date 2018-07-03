# Makefile.am -- 
# Copyright 2004-08,2015-16 Red Hat Inc., Durham, North Carolina.
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
#   Rickard E. (Rik) Faith <faith@redhat.com>
#

SUBDIRS = lib auparse src/libev src audisp tools bindings init.d \
	m4 docs rules
EXTRA_DIST = ChangeLog AUTHORS NEWS README INSTALL audit.spec \
        COPYING COPYING.LIB \
	contrib/skeleton.c contrib/avc_snap \
	contrib/plugin/Makefile contrib/plugin/audisp-example.c \
	contrib/plugin/audisp-example.conf
CONFIG_CLEAN_FILES = debug*.list config/*

clean-generic:
	rm -rf autom4te*.cache 
	rm -f *.rej *.orig *.lang
