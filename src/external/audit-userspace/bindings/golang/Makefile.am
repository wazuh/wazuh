# Makefile.am --
# Copyright 2014,16 Red Hat Inc., Durham, North Carolina.
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
EXTRA_DIST = audit.go
dist_check_SCRIPTS = test.go

if HAVE_GOLANG
LIBDIR = lib
GODIR = $(LIBDIR)/golang/src/pkg/redhat.com/audit

install:
	[ -d $(DESTDIR)${prefix}/$(GODIR) ] || mkdir -p $(DESTDIR)${prefix}/$(GODIR)
	install -m 644 ${top_srcdir}/bindings/golang/audit.go $(DESTDIR)${prefix}/$(GODIR)

uninstall:
	@rm -f $(DESTDIR)${prefix}/$(GODIR)/*

check:
	@mkdir audit
	@cp ${top_srcdir}/bindings/golang/audit.go audit
	@cp ${top_srcdir}/lib/libaudit.h audit
	## Disable for now. Golang doesn't allow overriding search 
	## paths from the command line.
	##[ -f test.go ] || cp ${top_srcdir}/bindings/golang/test.go .
	##PKG_CONFIG_PATH=${abs_top_builddir}/lib/:$(PKG_CONFIG_PATH) GOPATH=$(pwd) $(GOLANG) run test.go
	@rm -rf audit
endif

