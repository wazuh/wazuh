# Makefile for misc tests

maketest:
		$(CC) -g -o string_test string_test.c ../string_op.c -I../ -I../../ -I../../headers/ -I../headers/ -Wall
		$(CC) -g -o prime_test prime_test.c ../math_op.c -I../ -I../../ -I../../headers/ -I../headers/ -Wall
		$(CC) -g -o hash_test hash_test.c ../hash_op.c ../math_op.c -I../ -I../../ -I../../headers/ -I../headers/ -Wall
		$(CC) -g -o merge_test merge_test.c  ../file_op.c ../debug_op.c -I../ -I../../ -I../../headers/ -I../headers/ -Wall
		$(CC) -DARGV0=\"ip_test\" -g -o ip_test ip_test.c ../validate_op.c ../debug_op.c ../regex_op.c -I../ -I../../ -I../../headers/ -I../headers/ -Wall

clean:
		-rm string_test prime_test hash_test merge_test ip_test *.core
