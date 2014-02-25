# Copyright (C) 2014 Trend Micro Inc.
# All rights reserved.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation

PT=../
include ${PT}Config.Make

OBJS = ${OS_ZLIB}
CHECK_LINK = -lcheck -lm -pthread -lrt

run_tests: test_os_zlib
	./test_os_zlib

test_os_zlib: test_os_zlib.c
	${CC} ${CFLAGS} $+ ${OBJS} ${CHECK_LINK} -o $@
		
clean:
	${CLEAN} test_os_zlib
