#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "math_op.h"


int main(int argc, char **argv)
{
    if (!argv[1]) {
        printf("%s <int>\n", argv[0]);
        exit(1);
    }

    printf("Value: %d\n", os_getprime(atoi(argv[1])));

    return (0);
}

