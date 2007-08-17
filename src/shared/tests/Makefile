# Makefile for misc tests

maketest:
		$(CC) -g -o prime_test prime_test.c ../math_op.c -I../ -I../../ -I../../headers/ -I../headers/ -Wall
		$(CC) -g -o hash_test hash_test.c ../hash_op.c ../math_op.c -I../ -I../../ -I../../headers/ -I../headers/ -Wall

clean:
		-rm regex regex_str *.core
