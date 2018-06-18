# Makefile.am--
# Copyright 2007 Red Hat Inc., Durham, North Carolina.
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

CONFIG_CLEAN_FILES = *.rej *.orig
CONF_FILES = af_unix.conf syslog.conf
EXTRA_DIST = $(CONF_FILES)
plugin_confdir=$(sysconfdir)/audisp/plugins.d

install-data-hook:
	mkdir -p -m 0750 ${DESTDIR}${plugin_confdir}
	for i in $(CONF_FILES); do \
		$(INSTALL_DATA) -D -m 640 ${srcdir}/"$$i" \
			${DESTDIR}${plugin_confdir}; \
	done

uninstall-hook:
	for i in $(CONF_FILES); do \
		rm ${DESTDIR}${plugin_confdir}/"$$i"; \
	done

