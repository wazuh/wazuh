#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bf_op.h"


int main(int argc, char ** argv)
	{
	char *input="123456789";
	char *output=NULL;
	char *output2=NULL;

	output = OS_BF_Str(argv[1], "mykey12", strlen(argv[1]), OS_ENCRYPT);
	output2 = OS_BF_Str(output, "mykey12", strlen(argv[1]), OS_DECRYPT);

	printf("finished..\n");
	printf("input: %s\n",argv[1]);
	printf("output: %s\n",output);	
	printf("output2: %s\n",output2);	
	return(0);
	}
