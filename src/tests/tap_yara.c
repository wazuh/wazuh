#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../wazuh_modules/wmodules.h"
#include "../wazuh_modules/wm_yara.h"
#include "../wazuh_modules/wm_yara.c"

#include "tap.h"



int main(void) {
    printf("\n\n   STARTING TEST - YARA MODULE  \n\n");

    TAP_PLAN;
    TAP_SUMMARY;
    printf("\n   ENDING TEST  - YARA MODULE   \n\n");
    return 0;
}
