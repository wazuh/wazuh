# Makefile.am -- 
# Copyright 2006-08,2014-17 Red Hat Inc., Durham, North Carolina.
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

CONFIG_CLEAN_FILES = *.loT *.rej *.orig *.cur
AUTOMAKE_OPTIONS = no-dependencies
check_PROGRAMS = auparse_test auparselol_test lookup_test
dist_check_SCRIPTS = auparse_test.py
EXTRA_DIST = auparse_test.ref auparse_test.ref.py test.log test2.log test3.log auditd_raw.sed

AM_CPPFLAGS = -I${top_srcdir}/auparse -I${top_srcdir}/lib

lookup_test_SOURCES = lookup_test.c
lookup_test_LDADD = ${top_builddir}/auparse/libauparse.la \
	${top_builddir}/lib/libaudit.la

auparse_test_SOURCES = auparse_test.c
auparse_test_LDFLAGS = -static
auparse_test_LDADD = ${top_builddir}/auparse/libauparse.la \
	${top_builddir}/lib/libaudit.la

auparselol_test_SOURCES = auparselol_test.c
auparselol_test_LDFLAGS = -static
auparselol_test_LDADD = ${top_builddir}/auparse/libauparse.la \
	${top_builddir}/lib/libaudit.la

drop_srcdir = sed 's,$(srcdir)/test,test,'

check: auparse_test auparselol_test lookup_test
	test "$(top_srcdir)" = "$(top_builddir)" || \
			cp $(top_srcdir)/auparse/test/test*.log .
	LC_ALL=C \
	./auparse_test > auparse_test.cur
	diff -u $(top_srcdir)/auparse/test/auparse_test.ref auparse_test.cur
	./auparselol_test -f test3.log --check | sort > auparse_test.cur
	sed -f $(top_srcdir)/auparse/test/auditd_raw.sed test3.log | sort > auparse_test.raw
	diff -u auparse_test.raw auparse_test.cur
if HAVE_PYTHON
	cp ${top_builddir}/bindings/swig/python/.libs/_audit.so ${top_builddir}/bindings/swig/python
	PYTHONPATH=${top_builddir}/bindings/python/python2/.libs/:${top_builddir}/bindings/swig/python:${top_builddir}/bindings/swig/python/.libs \
	LD_LIBRARY_PATH=${top_builddir}/auparse/.libs \
		srcdir=$(srcdir) $(srcdir)/auparse_test.py \
		| $(drop_srcdir) > auparse_test.cur
	diff -u $(top_srcdir)/auparse/test/auparse_test.ref.py auparse_test.cur
endif
	./lookup_test
	echo -e "===================\nAuparse Test Passes\n==================="

diffcheck: auparse_test auparselol_test
	./auparse_test > auparse_test.cur
	diff -u $(srcdir)/auparse_test.ref auparse_test.cur
	./auparselol_test -f test3.log --check | sort > auparse_test.cur
	sed -f ./auditd_raw.sed test3.log | sort > auparse_test.raw
	diff -u auparse_test.raw auparse_test.cur

memcheck: auparse_test
	valgrind --leak-check=yes --show-reachable=yes ./auparse_test 

pycheck: auparse_test.py
if HAVE_PYTHON
	PYTHONPATH=${top_builddir}/bindings/python/python2/.libs/:${top_builddir}/bindings/swig/python:${top_builddir}/bindings/swig/python/.libs \
	LD_LIBRARY_PATH=${top_builddir}/auparse/.libs \
		srcdir=$(srcdir) $(srcdir)/auparse_test.py
endif

pydiffcheck: auparse_test.py 
if HAVE_PYTHON
	PYTHONPATH=${top_builddir}/bindings/python/python2/.libs/:${top_builddir}/bindings/swig/python:${top_builddir}/bindings/swig/python/.libs \
	LD_LIBRARY_PATH=${top_builddir}/auparse/.libs \
		srcdir=$(srcdir) $(srcdir)/auparse_test.py \
		| $(drop_srcdir) > auparse_test.cur
	diff $(srcdir)/auparse_test.ref auparse_test.cur
endif

pymemcheck: auparse_test.py
if HAVE_PYTHON
	PYTHONPATH=${top_builddir}/bindings/python/python2/.libs/:${top_builddir}/bindings/swig/python:${top_builddir}/bindings/swig/python/.libs \
	LD_LIBRARY_PATH=${top_builddir}/auparse/.libs srcdir=$(srcdir) valgrind --leak-check=yes --show-reachable=yes python $(srcdir)/auparse_test.py

${top_builddir}/bindings/python/build/*/auparse.so: ${top_srcdir}/bindings/python/auparse_python.c
	cd ${top_builddir}/bindings/python && make
endif

clean-generic:
	$(RM) *.cur
	$(RM) auparse_test.raw
if HAVE_PYTHON
	$(RM) ${top_builddir}/bindings/swig/python/_audit.so
endif
	test "$(top_srcdir)" = "$(top_builddir)" || $(RM) test*.log
