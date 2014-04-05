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
	-I../headers/

run_tests: build_tests
	./test_os_zlib
	./test_os_xml
	./test_os_regex
	
generate_coverage: build_tests
	lcov --base-directory . --directory . --zerocounters --quiet
	@echo "Running tests\n"
	
	./test_os_zlib
	./test_os_xml
	./test_os_regex
	
	@echo "\nTests finished."
	lcov --base-directory . --directory . --capture --quiet --output-file ossec.test
	rm -rf coverage-report/
	genhtml --output-directory coverage-report/ --title "ossec test coverage" --show-details --legend --num-spaces 4 --quiet ossec.test
	
	
build_tests: test_os_zlib test_os_xml test_os_regex

test_os_zlib: test_os_zlib.c ${OS_ZLIB}
	${CC} ${CFLAGS_TEST} $+ ${CHECK_LINK} -o $@

test_os_xml: test_os_xml.c ../os_xml/*.c ../os_xml/*.h
	${CC} ${CFLAGS_TEST} test_os_xml.c ../os_xml/*.c ${CHECK_LINK} -o $@
	
test_os_regex: test_os_regex.c ../os_regex/*.c ../os_regex/*.h
	${CC} ${CFLAGS_TEST} test_os_regex.c ../os_regex/*.c ${CHECK_LINK} -o $@


		
clean:
	${CLEAN} test_os_zlib test_os_xml test_os_regex coverage-report/ ossec.test
