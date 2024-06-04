#ifndef __TEST_FIM_H
#define __TEST_FIM_H

#include "../syscheckd/include/syscheck.h"
#include "../config/syscheck-config.h"

#include "wrappers/posix/pthread_wrappers.h"
#include "wrappers/wazuh/shared/debug_op_wrappers.h"
#include "wrappers/wazuh/shared/mq_op_wrappers.h"

/**********************************************************************************************************************\
 * Auxiliar expect functions
\**********************************************************************************************************************/
void expect_fim_send_msg(char mq, const char *location, const char *msg, int retval);
void expect_send_syscheck_msg(const char *msg);

void expect_fim_diff_delete_compress_folder(struct dirent *dir);

cJSON *create_win_permissions_object();

/**********************************************************************************************************************\
 * Setups/Teardowns
\**********************************************************************************************************************/
int setup_os_list(void **state);
int teardown_os_list(void **state);
int setup_rb_tree(void **state);
int teardown_rb_tree(void **state);

#endif // __TEST_FIM_H
