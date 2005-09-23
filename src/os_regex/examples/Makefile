# Makefile for os_regex auto tests

maketest:
		$(CC) -o regex regex.c ../os_regex.a -I../ -Wall
		$(CC) -o allmatch allmatch.c ../os_regex.a -I../ -Wall
		$(CC) -o regex_str regex_str.c ../os_regex.a -I../ -Wall

clean:
		-rm allmatch regex regex_str *.core
