# Makefile for os_regex tests
# Copyright (C) 2015-2019, Wazuh Inc.

maketest:
		$(CC) -o regex regex.c ../os_regex.a -I../ -Wall
		$(CC) -o match match.c ../os_regex.a -I../ -Wall
		$(CC) -o regex_str regex_str.c ../os_regex.a -I../ -Wall

clean:
		rm -f regex match regex_str *.core
