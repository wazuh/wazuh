# Makefile.am -- 
# Copyright 2006-08,2011-17 Red Hat Inc., Durham, North Carolina.
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

SUBDIRS = test
EXTRA_DIST = expression-design.txt
CLEANFILES = $(BUILT_SOURCES)
CONFIG_CLEAN_FILES = *.loT *.rej *.orig
AM_CFLAGS = -fPIC -DPIC -D_GNU_SOURCE -g ${DEBUG} -Wno-pointer-sign -Wno-enum-compare -Wno-switch
AM_CPPFLAGS = -I. -I${top_srcdir} -I${top_srcdir}/src -I${top_srcdir}/lib
LIBS =

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = auparse.pc
DISTCLEANFILES = $(pkgconfig_DATA)

lib_LTLIBRARIES = libauparse.la
include_HEADERS = auparse.h auparse-defs.h
libauparse_la_SOURCES = lru.c interpret.c nvlist.c ellist.c		\
	auparse.c auditd-config.c message.c data_buf.c strsplit.c	\
	auparse-defs.h	auparse-idata.h data_buf.h 			\
	nvlist.h auparse.h ellist.h					\
	internal.h lru.h rnode.h interpret.h				\
	private.h expression.c expression.h tty_named_keys.h		\
	normalize.c normalize-llist.c normalize-llist.h 		\
	normalize-internal.h normalize_obj_kind_map.h			\
	normalize_record_map.h normalize_syscall_map.h
nodist_libauparse_la_SOURCES = $(BUILT_SOURCES)

libauparse_la_LIBADD = ${top_builddir}/lib/libaudit.la
libauparse_la_DEPENDENCIES = $(libauparse_la_SOURCES) ${top_builddir}/config.h
libauparse_la_LDFLAGS = -Wl,-z,relro

message.c:
	cp ${top_srcdir}/lib/message.c .

strsplit.c:
	cp ${top_srcdir}/lib/strsplit.c .

BUILT_SOURCES = accesstabs.h captabs.h clocktabs.h clone-flagtabs.h \
	epoll_ctls.h famtabs.h fcntl-cmdtabs.h \
	flagtabs.h icmptypetabs.h ipctabs.h ipccmdtabs.h\
	ioctlreqtabs.h ipoptnametabs.h ip6optnametabs.h \
	mmaptabs.h mounttabs.h nfprototabs.h open-flagtabs.h \
	persontabs.h prctl_opttabs.h pktoptnametabs.h \
	prottabs.h ptracetabs.h \
	rlimittabs.h recvtabs.h schedtabs.h seccomptabs.h \
	seektabs.h shm_modetabs.h signaltabs.h sockoptnametabs.h \
	socktabs.h sockleveltabs.h socktypetabs.h \
	tcpoptnametabs.h typetabs.h umounttabs.h inethooktabs.h \
	netactiontabs.h \
	normalize_obj_kind_maps.h normalize_record_maps.h \
	normalize_syscall_maps.h normalize_evtypetabs.h
noinst_PROGRAMS = gen_accesstabs_h gen_captabs_h gen_clock_h \
	gen_clone-flagtabs_h \
	gen_epoll_ctls_h gen_famtabs_h \
	gen_fcntl-cmdtabs_h gen_flagtabs_h gen_ioctlreqtabs_h \
	gen_icmptypetabs_h gen_ipctabs_h gen_ipccmdtabs_h\
	gen_ipoptnametabs_h gen_ip6optnametabs_h gen_nfprototabs_h \
	gen_mmaptabs_h gen_mounttabs_h \
	gen_open-flagtabs_h gen_persontabs_h \
	gen_prctl_opttabs_h gen_pktoptnametabs_h gen_prottabs_h \
	gen_recvtabs_h gen_rlimit_h gen_ptracetabs_h \
	gen_schedtabs_h gen_seccomptabs_h \
	gen_seektabs_h gen_shm_modetabs_h gen_signals_h \
	gen_sockoptnametabs_h gen_socktabs_h gen_sockleveltabs_h \
	gen_socktypetabs_h gen_tcpoptnametabs_h gen_typetabs_h \
	gen_umounttabs_h gen_inethooktabs_h gen_netactiontabs_h \
	gen_normalize_record_map gen_normalize_syscall_map \
	gen_normalize_obj_kind_map gen_normalize_evtypetabs_h

gen_accesstabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h accesstab.h
gen_accesstabs_h_CFLAGS = '-DTABLE_H="accesstab.h"'
$(gen_accesstabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_accesstabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_accesstabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_accesstabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_accesstabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_accesstabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_accesstabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_accesstabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
accesstabs.h: gen_accesstabs_h Makefile
	./gen_accesstabs_h --i2s-transtab access > $@

gen_captabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h captab.h
gen_captabs_h_CFLAGS = '-DTABLE_H="captab.h"'
$(gen_captabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_captabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_captabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_captabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_captabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_captabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_captabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_captabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
captabs.h: gen_captabs_h Makefile
	./gen_captabs_h --i2s cap > $@

gen_clock_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h clocktab.h
gen_clock_h_CFLAGS = '-DTABLE_H="clocktab.h"'
$(gen_clock_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_clock_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_clock_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_clock_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_clock_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_clock_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_clock_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_clock_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
clocktabs.h: gen_clock_h Makefile
	./gen_clock_h --i2s clock > $@

gen_clone_flagtabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h \
	clone-flagtab.h
gen_clone_flagtabs_h_CFLAGS = '-DTABLE_H="clone-flagtab.h"'
$(gen_clone_flagtabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_clone_flagtabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_clone_flagtabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_clone_flagtabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_clone-flagtabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_clone-flagtabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_clone-flagtabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_clone-flagtabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
clone-flagtabs.h: gen_clone-flagtabs_h Makefile
	./gen_clone-flagtabs_h --i2s-transtab clone_flag > $@

gen_epoll_ctls_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h epoll_ctl.h
gen_epoll_ctls_h_CFLAGS = '-DTABLE_H="epoll_ctl.h"'
$(gen_epoll_ctls_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_epoll_ctls_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_epoll_ctls_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_epoll_ctls_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_epoll_ctls_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_epoll_ctls_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_epoll_ctls_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_epoll_ctls_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
epoll_ctls.h: gen_epoll_ctls_h Makefile
	./gen_epoll_ctls_h --i2s epoll_ctl > $@

gen_famtabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h famtab.h
gen_famtabs_h_CFLAGS = '-DTABLE_H="famtab.h"'
$(gen_famtabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_famtabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_famtabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_famtabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_famtabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_famtabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_famtabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_famtabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
famtabs.h: gen_famtabs_h Makefile
	./gen_famtabs_h --i2s fam > $@

gen_flagtabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h flagtab.h
# ../auparse/ is used to avoid using ../lib/flagtab.h
gen_flagtabs_h_CFLAGS = '-DTABLE_H="../auparse/flagtab.h"'
$(gen_flagtabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_flagtabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_flagtabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_flagtabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_flagtabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_flagtabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_flagtabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_flagtabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
flagtabs.h: gen_flagtabs_h Makefile
	./gen_flagtabs_h --i2s-transtab flag > $@

gen_fcntl_cmdtabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h \
	fcntl-cmdtab.h
gen_fcntl_cmdtabs_h_CFLAGS = '-DTABLE_H="fcntl-cmdtab.h"'
$(gen_fcntl_cmdtabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_fcntl_cmdtabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_fcntl_cmdtabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_fcntl_cmdtabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_fcntl-cmdtabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_fcntl-cmdtabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_fcntl-cmdtabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_fcntl-cmdtabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
fcntl-cmdtabs.h: gen_fcntl-cmdtabs_h Makefile
	./gen_fcntl-cmdtabs_h --i2s fcntl > $@

gen_icmptypetabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h icmptypetab.h
gen_icmptypetabs_h_CFLAGS = '-DTABLE_H="icmptypetab.h"'
$(gen_icmptypetabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_icmptypetabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_icmptypetabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_icmptypetabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_icmptypetabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_icmptypetabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_icmptypetabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_icmptypetabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
icmptypetabs.h: gen_icmptypetabs_h Makefile
	./gen_icmptypetabs_h --i2s icmptype > $@

gen_ioctlreqtabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h ioctlreqtab.h
gen_ioctlreqtabs_h_CFLAGS = '-DTABLE_H="ioctlreqtab.h"'
$(gen_ioctlreqtabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_ioctlreqtabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_ioctlreqtabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_ioctlreqtabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_ioctlreqtabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_ioctlreqtabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_ioctlreqtabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_ioctlreqtabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
ioctlreqtabs.h: gen_ioctlreqtabs_h Makefile
	./gen_ioctlreqtabs_h --i2s ioctlreq > $@

gen_ipctabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h ipctab.h
gen_ipctabs_h_CFLAGS = '-DTABLE_H="ipctab.h"'
$(gen_ipctabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_ipctabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_ipctabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_ipctabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_ipctabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_ipctabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_ipctabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_ipctabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
ipctabs.h: gen_ipctabs_h Makefile
	./gen_ipctabs_h --i2s ipc > $@

gen_ipccmdtabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h ipccmdtab.h
gen_ipccmdtabs_h_CFLAGS = '-DTABLE_H="ipccmdtab.h"'
$(gen_ipccmdtabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_ipccmdtabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_ipccmdtabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_ipccmdtabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_ipccmdtabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_ipccmdtabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_ipccmdtabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_ipccmdtabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
ipccmdtabs.h: gen_ipccmdtabs_h Makefile
	./gen_ipccmdtabs_h --i2s-transtab ipccmd > $@

gen_ipoptnametabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h ipoptnametab.h
gen_ipoptnametabs_h_CFLAGS = '-DTABLE_H="ipoptnametab.h"'
$(gen_ipoptnametabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_ipoptnametabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_ipoptnametabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_ipoptnametabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_ipoptnametabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_ipoptnametabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_ipoptnametabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_ipoptnametabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
ipoptnametabs.h: gen_ipoptnametabs_h Makefile
	./gen_ipoptnametabs_h --i2s ipoptname > $@

gen_ip6optnametabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h ip6optnametab.h
gen_ip6optnametabs_h_CFLAGS = '-DTABLE_H="ip6optnametab.h"'
$(gen_ip6optnametabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_ip6optnametabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_ip6optnametabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_ip6optnametabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_ip6optnametabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_ip6optnametabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_ip6optnametabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_ip6optnametabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
ip6optnametabs.h: gen_ip6optnametabs_h Makefile
	./gen_ip6optnametabs_h --i2s ip6optname > $@

gen_mmaptabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h mmaptab.h
gen_mmaptabs_h_CFLAGS = '-DTABLE_H="mmaptab.h"'
$(gen_mmaptabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_mmaptabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_mmaptabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_mmaptabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_mmaptabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_mmaptabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_mmaptabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_mmaptabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
mmaptabs.h: gen_mmaptabs_h Makefile
	./gen_mmaptabs_h --i2s-transtab mmap > $@

gen_mounttabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h mounttab.h
gen_mounttabs_h_CFLAGS = '-DTABLE_H="mounttab.h"'
$(gen_mounttabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_mounttabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_mounttabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_mounttabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_mounttabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_mounttabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_mounttabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_mounttabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
mounttabs.h: gen_mounttabs_h Makefile
	./gen_mounttabs_h --i2s-transtab mount > $@

gen_nfprototabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h nfprototab.h
gen_nfprototabs_h_CFLAGS = '-DTABLE_H="nfprototab.h"'
$(gen_nfprototabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_nfprototabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_nfprototabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_nfprototabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_nfprototabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_nfprototabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_nfprototabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_nfprototabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
nfprototabs.h: gen_nfprototabs_h Makefile
	./gen_nfprototabs_h --i2s nfproto > $@

gen_open_flagtabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h \
	open-flagtab.h
gen_open_flagtabs_h_CFLAGS = '-DTABLE_H="open-flagtab.h"'
$(gen_open_flagtabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_open_flagtabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_open_flagtabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_open_flagtabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_open-flagtabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_open-flagtabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_open-flagtabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_open-flagtabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
open-flagtabs.h: gen_open-flagtabs_h Makefile
	./gen_open-flagtabs_h --i2s-transtab open_flag > $@

gen_persontabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h persontab.h
gen_persontabs_h_CFLAGS = '-DTABLE_H="persontab.h"'
$(gen_persontabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_persontabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_persontabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_persontabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_persontabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_persontabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_persontabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_persontabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
persontabs.h: gen_persontabs_h Makefile
	./gen_persontabs_h --i2s person > $@

gen_ptracetabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h ptracetab.h
gen_ptracetabs_h_CFLAGS = '-DTABLE_H="ptracetab.h"'
$(gen_ptracetabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_ptracetabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_ptracetabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_ptracetabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_ptracetabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_ptracetabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_ptracetabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_ptracetabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
ptracetabs.h: gen_ptracetabs_h Makefile
	./gen_ptracetabs_h --i2s ptrace > $@

gen_prctl_opttabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h prctl-opt-tab.h
gen_prctl_opttabs_h_CFLAGS = '-DTABLE_H="prctl-opt-tab.h"'
$(gen_prctl_opttabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_prctl_opttabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_prctl_opttabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_prctl_opttabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_prctl_opttabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_prctl_opttabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_prctl_opttabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_prctl_opttabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
prctl_opttabs.h: gen_prctl_opttabs_h Makefile
	./gen_prctl_opttabs_h --i2s prctl_opt > $@

gen_pktoptnametabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h pktoptnametab.h
gen_pktoptnametabs_h_CFLAGS = '-DTABLE_H="pktoptnametab.h"'
$(gen_pktoptnametabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_pktoptnametabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_pktoptnametabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_pktoptnametabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_pktoptnametabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_pktoptnametabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_pktoptnametabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_pktoptnametabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
pktoptnametabs.h: gen_pktoptnametabs_h Makefile
	./gen_pktoptnametabs_h --i2s pktoptname > $@

gen_prottabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h prottab.h
gen_prottabs_h_CFLAGS = '-DTABLE_H="prottab.h"'
$(gen_prottabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_prottabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_prottabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_prottabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_prottabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_prottabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_prottabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_prottabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
prottabs.h: gen_prottabs_h Makefile
	./gen_prottabs_h --i2s-transtab prot > $@

gen_recvtabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h recvtab.h
gen_recvtabs_h_CFLAGS = '-DTABLE_H="recvtab.h"'
$(gen_recvtabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_recvtabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_recvtabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_recvtabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_recvtabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_recvtabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_recvtabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_recvtabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
recvtabs.h: gen_recvtabs_h Makefile
	./gen_recvtabs_h --i2s-transtab recv > $@

gen_rlimit_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h rlimittab.h
gen_rlimit_h_CFLAGS = '-DTABLE_H="rlimittab.h"'
$(gen_rlimit_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_rlimit_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_rlimit_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_rlimit_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_rlimit_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_rlimit_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_rlimit_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_rlimit_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
rlimittabs.h: gen_rlimit_h Makefile
	./gen_rlimit_h --i2s rlimit > $@

gen_schedtabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h schedtab.h
gen_schedtabs_h_CFLAGS = '-DTABLE_H="schedtab.h"'
$(gen_schedtabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_schedtabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_schedtabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_schedtabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_schedtabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_schedtabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_schedtabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_schedtabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
schedtabs.h: gen_schedtabs_h Makefile
	./gen_schedtabs_h --i2s sched > $@

gen_seccomptabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h seccomptab.h
gen_seccomptabs_h_CFLAGS = '-DTABLE_H="seccomptab.h"'
$(gen_seccomptabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_seccomptabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_seccomptabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_seccomptabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_seccomptabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_seccomptabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_seccomptabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_seccomptabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
seccomptabs.h: gen_seccomptabs_h Makefile
	./gen_seccomptabs_h --i2s seccomp > $@

gen_seektabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h seektab.h
gen_seektabs_h_CFLAGS = '-DTABLE_H="seektab.h"'
$(gen_seektabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_seektabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_seektabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_seektabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_seektabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_seektabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_seektabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_seektabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
seektabs.h: gen_seektabs_h Makefile
	./gen_seektabs_h --i2s seek > $@

gen_shm_modetabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h shm_modetab.h
gen_shm_modetabs_h_CFLAGS = '-DTABLE_H="shm_modetab.h"'
$(gen_shm_modetabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_shm_modetabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_shm_modetabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_shm_modetabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_shm_modetabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_shm_modetabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_shm_modetabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_shm_modetabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
shm_modetabs.h: gen_shm_modetabs_h Makefile
	./gen_shm_modetabs_h --i2s-transtab shm_mode > $@

gen_signals_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h signaltab.h
gen_signals_h_CFLAGS = '-DTABLE_H="signaltab.h"'
$(gen_signals_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_signals_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_signals_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_signals_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_signals_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_signals_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_signals_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_signals_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
signaltabs.h: gen_signals_h Makefile
	./gen_signals_h --i2s signal > $@

gen_sockleveltabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h sockleveltab.h
gen_sockleveltabs_h_CFLAGS = '-DTABLE_H="sockleveltab.h"'
$(gen_sockleveltabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_sockleveltabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_sockleveltabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_sockleveltabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_sockleveltabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_sockleveltabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_sockleveltabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_sockleveltabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
sockleveltabs.h: gen_sockleveltabs_h Makefile
	./gen_sockleveltabs_h --i2s socklevel > $@

gen_sockoptnametabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h sockoptnametab.h
gen_sockoptnametabs_h_CFLAGS = '-DTABLE_H="sockoptnametab.h"'
$(gen_sockoptnametabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_sockoptnametabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_sockoptnametabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_sockoptnametabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_sockoptnametabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_sockoptnametabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_sockoptnametabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_sockoptnametabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
sockoptnametabs.h: gen_sockoptnametabs_h Makefile
	./gen_sockoptnametabs_h --i2s sockoptname > $@

gen_socktabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h socktab.h
gen_socktabs_h_CFLAGS = '-DTABLE_H="socktab.h"'
$(gen_socktabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_socktabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_socktabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_socktabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_socktabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_socktabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_socktabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_socktabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
socktabs.h: gen_socktabs_h Makefile
	./gen_socktabs_h --i2s sock > $@

gen_socktypetabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h socktypetab.h
gen_socktypetabs_h_CFLAGS = '-DTABLE_H="socktypetab.h"'
$(gen_socktypetabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_socktypetabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_socktypetabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_socktypetabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_socktypetabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_socktypetabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_socktypetabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_socktypetabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
socktypetabs.h: gen_socktypetabs_h Makefile
	./gen_socktypetabs_h --i2s sock_type > $@

gen_tcpoptnametabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h tcpoptnametab.h
gen_tcpoptnametabs_h_CFLAGS = '-DTABLE_H="tcpoptnametab.h"'
$(gen_tcpoptnametabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_tcpoptnametabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_tcpoptnametabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_tcpoptnametabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_tcpoptnametabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_tcpoptnametabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_tcpoptnametabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_tcpoptnametabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
tcpoptnametabs.h: gen_tcpoptnametabs_h Makefile
	./gen_tcpoptnametabs_h --i2s tcpoptname > $@

gen_typetabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h typetab.h
gen_typetabs_h_CFLAGS = '-DTABLE_H="typetab.h"'
$(gen_typetabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_typetabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_typetabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_typetabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_typetabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_typetabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_typetabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_typetabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
typetabs.h: gen_typetabs_h Makefile
	./gen_typetabs_h --s2i type > $@

gen_umounttabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h umounttab.h
gen_umounttabs_h_CFLAGS = '-DTABLE_H="umounttab.h"'
$(gen_umounttabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_umounttabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_umounttabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_umounttabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_umounttabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_umounttabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_umounttabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_umounttabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
umounttabs.h: gen_umounttabs_h Makefile
	./gen_umounttabs_h --i2s-transtab umount > $@

gen_inethooktabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h inethooktab.h
gen_inethooktabs_h_CFLAGS = '-DTABLE_H="inethooktab.h"'
$(gen_inethooktabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_inethooktabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_inethooktabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_inethooktabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_inethooktabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_inethooktabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_inethooktabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_inethooktabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
inethooktabs.h: gen_inethooktabs_h Makefile
	./gen_inethooktabs_h --i2s inethook > $@

gen_netactiontabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h netactiontab.h
gen_netactiontabs_h_CFLAGS = '-DTABLE_H="netactiontab.h"'
$(gen_netactiontabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_netactiontabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_netactiontabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_netactiontabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_netactiontabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_netactiontabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_netactiontabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_netactiontabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
netactiontabs.h: gen_netactiontabs_h Makefile
	./gen_netactiontabs_h --i2s netaction > $@

gen_normalize_record_map_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h normalize_record_map.h
gen_normalize_record_map_CFLAGS = '-DTABLE_H="normalize_record_map.h"'
$(gen_normalize_record_map_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_normalize_record_map_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_normalize_record_map_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_normalize_record_map_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_normalize_record_map$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_normalize_record_map$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_normalize_record_map$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_normalize_record_map$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
normalize_record_maps.h: gen_normalize_record_map Makefile
	./gen_normalize_record_map --lowercase --i2s normalize_record_map > $@

gen_normalize_syscall_map_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h normalize_syscall_map.h
gen_normalize_syscall_map_CFLAGS = '-DTABLE_H="normalize_syscall_map.h"'
$(gen_normalize_syscall_map_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_normalize_syscall_map_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_normalize_syscall_map_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_normalize_syscall_map_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_normalize_syscall_map$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_normalize_syscall_map$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_normalize_syscall_map$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_normalize_syscall_map$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
normalize_syscall_maps.h: gen_normalize_syscall_map Makefile
	./gen_normalize_syscall_map --lowercase --s2i normalize_syscall_map > $@

gen_normalize_obj_kind_map_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h normalize_obj_kind_map.h
gen_normalize_obj_kind_map_CFLAGS = '-DTABLE_H="normalize_obj_kind_map.h"'
$(gen_normalize_obj_kind_map_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_normalize_obj_kind_map_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_normalize_obj_kind_map_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_normalize_obj_kind_map_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_normalize_obj_kind_map$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_normalize_obj_kind_map$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_normalize_obj_kind_map$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_normalize_obj_kind_map$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
normalize_obj_kind_maps.h: gen_normalize_obj_kind_map Makefile
	./gen_normalize_obj_kind_map --lowercase --i2s normalize_obj_kind_map > $@

gen_normalize_evtypetabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h normalize_evtypetab.h
gen_normalize_evtypetabs_h_CFLAGS = '-DTABLE_H="normalize_evtypetab.h"'
$(gen_normalize_evtypetabs_h_OBJECTS): CC=$(CC_FOR_BUILD)
$(gen_normalize_evtypetabs_h_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_normalize_evtypetabs_h_OBJECTS): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_normalize_evtypetabs_h_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
gen_normalize_evtypetabs_h$(BUILD_EXEEXT): CC=$(CC_FOR_BUILD)
gen_normalize_evtypetabs_h$(BUILD_EXEEXT): CFLAGS=$(CFLAGS_FOR_BUILD)
gen_normalize_evtypetabs_h$(BUILD_EXEEXT): CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
gen_normalize_evtypetabs_h$(BUILD_EXEEXT): LDFLAGS=$(LDFLAGS_FOR_BUILD)
normalize_evtypetabs.h: gen_normalize_evtypetabs_h Makefile
	./gen_normalize_evtypetabs_h --i2s evtype > $@

