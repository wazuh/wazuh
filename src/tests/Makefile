# Copyright (C) 2014 Trend Micro Inc.
# All rights reserved.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation

PT=../
include ${PT}Config.Make

CHECK_LINK = -lcheck -lm -pthread -lrt
CFLAGS_TEST = -std=gnu99 -fstrict-overflow -Wstrict-overflow=4 \
	-fstrict-aliasing -Wstrict-aliasing=3 -Wabi -Wpedantic -Wall -Wextra \
	-Wdouble-promotion -Wformat=2 -Winit-self -Wmissing-include-dirs \
	-Wswitch-default -Wunused -Wsuggest-attribute=const \
	-Wsuggest-attribute=noreturn -Wsuggest-attribute=format -Wfloat-equal \
	-Wundef -Wshadow -Wbad-function-cast -Wcast-qual -Wcast-align \
	-Wwrite-strings -Wconversion -Wlogical-op -Waggregate-return \
	-Wstrict-prototypes -Wold-style-declaration -Wmissing-prototypes \
	-Wmissing-declarations -Wredundant-decls -Wnested-externs -Winline \
	-Wc++-compat -Winvalid-pch -Wswitch-enum \
	-g -O0 --coverage \
	-I../ \
	-I../headers/ \
	-DARGV0=\"ossec-test\"

run_tests: build_tests
	./test_shared


run_valgrind: build_tests
	valgrind --leak-check=full --track-origins=yes --trace-children=yes --vgdb=no --error-exitcode=1 --gen-suppressions=all --suppressions=valgrind.supp make run_tests


generate_coverage: build_tests
	lcov --base-directory . --directory . --zerocounters --rc lcov_branch_coverage=1 --quiet
	@echo "Running tests\n"

	make run_tests

	@echo "\nTests finished."
	lcov --base-directory . --directory . --capture --quiet --rc lcov_branch_coverage=1 --output-file ossec.test
	rm -rf coverage-report/
	genhtml --branch-coverage --output-directory coverage-report/ --title "ossec test coverage" --show-details --legend --num-spaces 4 --quiet ossec.test


build_tests: test_os_zlib test_os_xml test_os_regex test_os_crypto test_os_net test_shared

test_os_zlib: test_os_zlib.c ${OS_ZLIB}
	${CC} ${CFLAGS_TEST} $+ ${CHECK_LINK} -o $@

test_os_xml: test_os_xml.c ../os_xml/*.c ../os_xml/*.h
	${CC} ${CFLAGS_TEST} test_os_xml.c ../os_xml/*.c ${CHECK_LINK} -o $@

test_os_regex: test_os_regex.c ../os_regex/*.c ../os_regex/*.h
	${CC} ${CFLAGS_TEST} test_os_regex.c ../os_regex/*.c ${CHECK_LINK} -o $@

BLOWFISH_SRCS = ../os_crypto/blowfish/bf_op.c ../os_crypto/blowfish/bf_skey.c ../os_crypto/blowfish/bf_enc.c
MD5_SRCS = ../os_crypto/md5/md5.c ../os_crypto/md5/md5_op.c
SHA1_SRCS = ../os_crypto/sha1/sha1_op.c
test_os_crypto: test_os_crypto.c ../os_crypto/blowfish/*.h ${BLOWFISH_SRCS} ../os_crypto/md5/*.h ${MD5_SRCS} ../os_crypto/sha1/*.h ${SHA1_SRCS}  ../os_crypto/md5_sha1/md5_sha1_op.h  ../os_crypto/md5_sha1/md5_sha1_op.c
	${CC} ${CFLAGS_TEST} test_os_crypto.c ${BLOWFISH_SRCS} ${MD5_SRCS} ${SHA1_SRCS} ../os_crypto/md5_sha1/md5_sha1_op.c ${CHECK_LINK} -o $@

test_os_net: test_os_net.c ../os_net/os_net.c ../os_net/os_net.h ../shared/debug_op.c ../shared/file_op.c
	${CC} ${CFLAGS_TEST} test_os_net.c ../os_net/os_net.c ../shared/debug_op.c ../shared/file_op.c ${CHECK_LINK} -o $@

SHARED_SRCS = ../shared/custom_output_search_replace.c ../shared/debug_op.c
test_shared: test_shared.c ${SHARED_SRCS} ../headers/*.h
	${CC} ${CFLAGS_TEST} test_shared.c ${SHARED_SRCS} ${CHECK_LINK} -o $@

clean:
	${CLEAN} test_os_zlib test_os_xml test_os_regex test_os_crypto test_os_net test_shared coverage-report/ ossec.test
