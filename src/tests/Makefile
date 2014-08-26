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
CFLAGS_TEST = -Waggregate-return -Wall -Wbad-function-cast -Wc++-compat -Wcast-align \
	-Wcast-qual -Wconversion -Wextra -Wfloat-equal -Wformat=2 -Winit-self -Winline \
	-Winvalid-pch -Wlogical-op -Wmissing-declarations -Wmissing-include-dirs \
	-Wmissing-prototypes -Wnested-externs -Wold-style-definition -Wredundant-decls \
	-Wshadow -Wstack-protector -Wstrict-aliasing -Wstrict-overflow=4 \
	-Wstrict-prototypes -Wswitch-default -Wswitch-enum -Wsync-nand -Wundef -Wunused \
	-Wwrite-strings \
	-g -O0 --coverage \
	-I../ \
	-I../headers/

run_tests: build_tests
	./test_os_zlib
	./test_os_xml
	./test_os_regex
	./test_os_crypto
	./test_os_net


run_valgrind: build_tests
	valgrind --leak-check=full --track-origins=yes --trace-children=yes --vgdb=no --error-exitcode=1 --gen-suppressions=all --suppressions=valgrind.supp make run_tests


generate_coverage: build_tests
	lcov --base-directory . --directory . --zerocounters --rc lcov_branch_coverage=1 --quiet
	@echo "Running tests\n"

	./test_os_zlib
	./test_os_xml
	./test_os_regex
	./test_os_crypto
	./test_os_net

	@echo "\nTests finished."
	lcov --base-directory . --directory . --capture --quiet --rc lcov_branch_coverage=1 --output-file ossec.test
	rm -rf coverage-report/
	genhtml --branch-coverage --output-directory coverage-report/ --title "ossec test coverage" --show-details --legend --num-spaces 4 --quiet ossec.test


build_tests: test_os_zlib test_os_xml test_os_regex test_os_crypto test_os_net

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

test_os_net: test_os_net.c ../os_net/os_net.c ../os_net/os_net.h ../shared/debug_op.c
	${CC} ${CFLAGS_TEST} test_os_net.c ../os_net/os_net.c ../shared/debug_op.c ${CHECK_LINK} -o $@


clean:
	${CLEAN} test_os_zlib test_os_xml test_os_regex test_os_crypto test_os_net coverage-report/ ossec.test
