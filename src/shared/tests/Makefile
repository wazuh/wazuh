# Makefile for misc tests
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

maketest:
		#$(CC) -g -o string_test string_test.c ../string_op.c -I../ -I../../ -I../../headers/ -I../headers/ -Wall
		#$(CC) -g -o prime_test prime_test.c ../math_op.c -I../ -I../../ -I../../headers/ -I../headers/ -Wall
		#$(CC) -g -o hash_test hash_test.c ../hash_op.c ../math_op.c -I../ -I../../ -I../../headers/ -I../headers/ -Wall
		$(CC) -g -o merge_test merge_test.c  ../file_op.c ../debug_op.c -I../ -I../../ -I../../headers/ -I../headers/ -Wall
		#$(CC) -DARGV0=\"ip_test\" -g -o ip_test ip_test.c ../validate_op.c ../debug_op.c ../regex_op.c -I../ -I../../ -I../../headers/ -I../headers/ -Wall

clean:
		-rm string_test prime_test hash_test merge_test ip_test *.core
