# Copyright (C) 2014 Trend Micro Inc.
# All rights reserved.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation

PT=../
ZLIB_DIR=zlib-1.2.8
include ${PT}Config.Make

zlib: libz.a
	cp -pr ${ZLIB_DIR}/zlib.h ${ZLIB_DIR}/zconf.h ../headers/

libz.a:
	cd ${ZLIB_DIR}/; ./configure; make libz.a;
	cp -pr ${ZLIB_DIR}/libz.a .
		
clean:
	${CLEAN} zlib.a ../headers/zlib.h ../headers/zconf.h
	cd ${ZLIB_DIR}/; make distclean
