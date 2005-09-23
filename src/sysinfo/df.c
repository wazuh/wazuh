#include <stdio.h>
#include "statfs.h"

int main()
	{
	if(getstatfspath() != 0)
		printf("error..\n");
	return(0);
	}
