#ifndef PARSER_H
#define PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <regex.h>

#define MAX_STR_LEN 1024
#define MAX_SIZE 4096
#define DEBUG 0

typedef int bool;
#define true 1
#define false 0

struct KeyStore{
	char original[MAX_SIZE];
	char match[MAX_SIZE];
	char msg[MAX_SIZE];
	char shost[MAX_STR_LEN];
	char src[MAX_STR_LEN];
	char location[MAX_STR_LEN];
	char sntdom[MAX_STR_LEN];
	char cn1[MAX_STR_LEN];
	char duser[MAX_STR_LEN];
	char destinationDnsDomain[MAX_STR_LEN];
	char externalId[MAX_STR_LEN];
	char duid[MAX_STR_LEN];
	char ip[MAX_STR_LEN];
	char cat[MAX_STR_LEN];
};

void parseString(char *inputString, char fieldname[MAX_STR_LEN], struct KeyStore*);
void findMatch(int regexIndex, char field[MAX_STR_LEN], char inputString[MAX_SIZE], struct KeyStore*);

#endif

