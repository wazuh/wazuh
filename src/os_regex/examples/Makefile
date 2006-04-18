# Makefile for os_regex tests

maketest:
		$(CC) -o regex regex.c ../os_regex.a -I../ -Wall
		$(CC) -o match match.c ../os_regex.a -I../ -Wall
		$(CC) -o newmatch newmatch.c ../os_regex.a -I../ -Wall
		$(CC) -o newmatch2 newmatch2.c ../os_regex.a -I../ -Wall
		$(CC) -o match2 match2.c ../os_regex.a -I../ -Wall
		$(CC) -o regex_str regex_str.c ../os_regex.a -I../ -Wall

clean:
		-rm regex regex_str *.core
